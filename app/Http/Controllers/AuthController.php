<?php

namespace App\Http\Controllers;

use App\Mail\AccountRecoveryOtpMail;
use App\Mail\VerifyEmailOtpMail;
use App\Models\AccountRecovery;
use Carbon\Carbon;
use Illuminate\Auth\Events\Registered;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use PragmaRX\Google2FA\Google2FA;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        // ✅ Validate only user inputs (excluding OTP)
        $fields = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|min:6',
        ]);

        // ✅ Generate OTP and expiry time separately
        $otp = rand(100000, 999999);
        $otpExpiresAt = Carbon::now()->addMinutes(10);

        // ✅ Create the user with hashed password
        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => Hash::make($fields['password']),
            'email_otp' => $otp,
            'otp_expires_at' => $otpExpiresAt
        ]);

        // ✅ Send OTP Email
        Mail::to($user->email)->send(new VerifyEmailOtpMail($otp));

        return response()->json([
            'message' => 'User registered! Please check your email for the OTP.',
            'user' => $user
        ], 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
            'password' => 'required',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Please verify your email before logging in.'
            ], 403);
        }

        if (!Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Incorrect credentials'], 401);
        }

        $sessionId = session()->getId();
        $ipAddress = $request->ip();
        $userAgent = $request->header('User-Agent');
        $lastActivity = Carbon::now()->timestamp;

        // ✅ Check if user has 2FA enabled
        if ($user->two_factor_confirmed_at) {
            $sessionData = [
                'email' => $user->email,
                '2fa_required' => true,
                'session_id' => $sessionId,
            ];

            // Encrypt and set the cookie
            $cookie = cookie(
                '_2fa_session',
                encrypt(json_encode($sessionData)),
                15, // Expire in 15 minutes
                '/',
                null,
                config('session.secure'),
                config('session.http_only'),
                false,
                config('session.same_site')
            );

            return response()->json([
                'success' => true,
                'status' => 200,
                'message' => 'Please provide the OTP.',
            ])->withCookie($cookie);
        }

        // ✅ If no 2FA is enabled, issue a token and store session
        $token = $user->createToken($user->name);
        $expiresAt = Carbon::now()->addDays(7);

        $latestToken = $user->tokens()->latest()->first();
        if ($latestToken) {
            $latestToken->update(['expires_at' => $expiresAt]);
        }

        DB::table('sessions')->insert([
            'id' => $sessionId,
            'user_id' => $user->id,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'payload' => base64_encode(json_encode([
                'token' => $token->plainTextToken,
                'expires_at' => $expiresAt,
            ])),
            'last_activity' => $lastActivity,
        ]);

        return response()->json([
            'user' => $user,
            'token' => [
                'accessToken' => $latestToken,
                'plainTextToken' => $token->plainTextToken,
            ]
        ]);
    }

    public function verifyLoginOtp(Request $request)
    {
        $request->validate([
            'two_factor_code' => 'required|numeric',
        ]);

        // ✅ Retrieve and validate the `_2fa_session` cookie
        $cookie = $request->cookie('_2fa_session');
        if (!$cookie) {
            return response()->json(['message' => '2FA session cookie is missing or expired'], 403);
        }

        try {
            $sessionData = json_decode(Crypt::decrypt($cookie), true);
        } catch (\Exception $e) {
            return response()->json(['message' => 'Invalid 2FA session cookie'], 403);
        }

        // Validate session state
        if (empty($sessionData['2fa_required']) || !$sessionData['2fa_required']) {
            return response()->json(['message' => '2FA is not required for this session'], 403);
        }

        $user = User::where('email', $sessionData['email'])->first();

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        if (!$user->two_factor_secret) {
            return response()->json(['message' => '2FA is not enabled for this user'], 400);
        }

        // ✅ Verify the 2FA code
        $google2fa = new Google2FA();
        $isValid = $google2fa->verifyKey(decrypt($user->two_factor_secret), $request->two_factor_code);

        if (!$isValid) {
            return response()->json(['message' => 'Invalid 2FA code'], 403);
        }

        // ✅ If 2FA is correct, issue the access token
        $token = $user->createToken($user->name);
        $expiresAt = Carbon::now()->addDays(7);

        $latestToken = $user->tokens()->latest()->first();
        if ($latestToken) {
            $latestToken->update(['expires_at' => $expiresAt]);
        }

        // ✅ Store Session Manually
        DB::table('sessions')->insert([
            'id' => session()->getId(), // Generate a session ID
            'user_id' => $user->id,
            'ip_address' => $request->ip(),
            'user_agent' => $request->header('User-Agent'),
            'payload' => base64_encode(json_encode([
                'token' => $token->plainTextToken,
                'expires_at' => $expiresAt
            ])), // Store the token info securely
            'last_activity' => Carbon::now()->timestamp
        ]);

        // Clear the `_2fa_session` cookie after successful login
        return response()->json([
            'user' => $user->makeHidden(['two_factor_secret', 'two_factor_recovery_codes']), // Hide sensitive fields
            'token' => [
                'accessToken' => $latestToken,
                'plainTextToken' => $token->plainTextToken
            ]
        ])->withCookie(cookie()->forget('_2fa_session'));
    }


    public function logout(Request $request){
        $user = $request->user();

        if (!$user) {
            return response()->json(['message' => 'Not authenticated'], 401);
        }

        // Get the current token model
        $currentToken = $user->currentAccessToken();

        if (!$currentToken) {
            return response()->json(['message' => 'No active session found'], 404);
        }

        $tokenId = $currentToken->id; // Get token ID (e.g., 23)

        // Retrieve all user sessions
        $sessions = DB::table('sessions')->where('user_id', $user->id)->get();

        foreach ($sessions as $session) {
            $payload = json_decode(base64_decode($session->payload), true);

            if (isset($payload['token'])) {
                // Extract the first part before "|" (token ID) and compare
                $storedTokenParts = explode('|', $payload['token']);
                $storedTokenId = $storedTokenParts[0] ?? null; // Get token ID from session

                if ($storedTokenId == $tokenId) {
                    DB::table('sessions')->where('id', $session->id)->delete();
                    break;
                }
            }
        }

        // Revoke the current token
        $currentToken->delete();

        return response()->json(['message' => 'Logged out successfully.']);
    }

    public function currentUserSessions(Request $request)
    {
        // Get the current authenticated user
        $user = $request->user();

        if (!$user) {
            return response()->json(['message' => 'User not authenticated'], 401);
        }

        // Retrieve all sessions associated with the current user
        $sessions = DB::table('sessions')->where('user_id', $user->id)->get();

        // Prepare sessions for response
        $formattedSessions = $sessions->map(function ($session) {
            $payload = json_decode(base64_decode($session->payload), true);

            // Optionally, you can format the session data
            return [
                'id' => $session->id,
                'ip_address' => $session->ip_address,
                'user_agent' => $session->user_agent,
                'last_activity' => Carbon::createFromTimestamp($session->last_activity)->toDateTimeString(),
            ];
        });

        return response()->json([
            'success' => true,
            'sessions' => $formattedSessions
        ]);
    }

    public function verifyOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
            'otp' => 'required|integer',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || $user->email_otp !== $request->otp || Carbon::now()->greaterThan($user->otp_expires_at)) {
            return response()->json([
                'message' => 'Invalid or expired OTP.'
            ], 400);
        }

        // ✅ Mark email as verified
        $user->email_verified_at = now();
        $user->email_otp = null;
        $user->otp_expires_at = null;
        $user->save();

        return response()->json([
            'message' => 'Email verified successfully.'
        ], 200);
    }


    public function resendOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
        ]);

        $user = User::where('email', $request->email)->first();

        if ($user->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Email already verified.'
            ], 400);
        }

        // ✅ Generate new OTP
        $otp = rand(100000, 999999);
        $user->email_otp = $otp;
        $user->otp_expires_at = Carbon::now()->addMinutes(10);
        $user->save();

        // ✅ Send OTP Email
        Mail::to($user->email)->send(new VerifyEmailOtpMail($otp));

        return response()->json([
            'message' => 'OTP resent successfully.'
        ], 200);
    }

    public function updateUserInfo(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'current_password' => 'required|string',
        ]);

        $user = $request->user();

        // ✅ Verify the current password before updating
        if (!Hash::check($request->current_password, $user->password)) {
            return response()->json([
                'message' => 'Incorrect current password.'
            ], 403);
        }

        // ✅ Update user info
        $user->name = $request->name;
        $user->save();

        return response()->json([
            'message' => 'User information updated successfully.',
            'user' => $user
        ], 200);
    }

    public function updateUserPassword(Request $request)
    {
        $request->validate([
            'current_password' => 'required|string',
            'new_password' => 'required|string|min:6|confirmed|different:current_password',
        ]);

        $user = $request->user();

        if (!Hash::check($request->current_password, $user->password)) {
            return response()->json([
                'message' => 'Incorrect current password.'
            ], 403);
        }

        $user->password = Hash::make($request->new_password);
        $user->save();

        return response()->json([
            'message' => 'Password updated successfully.'
        ], 200);
    }

    public function sendResetPasswordInstruction(Request $request)
    {
        $request->validate(['email' => 'required|email|exists:users,email']);

        $status = Password::sendResetLink($request->only('email'));

        if ($status === Password::RESET_LINK_SENT) {
            return response()->json(['message' => 'Password reset link sent!'], 200);
        }

        return response()->json(['message' => 'Error sending reset link.'], 500);
    }

    public function completeResetPassword(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
            'token' => 'required|string',
            'password' => 'required|string|min:6|confirmed',
        ]);

        $status = Password::reset(
            $request->only('email', 'token', 'password', 'password_confirmation'),
            function ($user, $password) {
                $user->forceFill([
                    'password' => Hash::make($password),
                ])->save();
            }
        );

        if ($status === Password::PASSWORD_RESET) {
            return response()->json([
                'message' => 'Password has been successfully reset!',
            ], 200);
        }

        return response()->json([
            'message' => 'Invalid or expired token.',
        ], 400);
    }

    public function redirectToGoogle()
    {
        return Socialite::driver('google')->stateless()->redirect();
    }

    public function handleGoogleCallback(Request $request)
    {
        try {
            // Get Google access token from request body
            $googleToken = $request->input('token');

            // Fetch user data from Google
            $googleUser = Socialite::driver('google')->stateless()->userFromToken($googleToken);

            // Find existing user by email
            $user = User::where('email', $googleUser->getEmail())->first();

            if ($user) {
                // Update Google ID and other details if the user exists
                $user->update([
                    'google_id' => $googleUser->getId(),
                    'name' => $googleUser->getName(), // Optional: Update name if needed
                ]);
            } else {
                // Create new user if no matching email is found
                $user = User::create([
                    'name' => $googleUser->getName(),
                    'email' => $googleUser->getEmail(),
                    'google_id' => $googleUser->getId(),
                    'password' => bcrypt(uniqid()), // Random password for new users
                ]);
            }

            // Create a Sanctum token
            $token = $user->createToken($user->name);
            $expiresAt = Carbon::now()->addDays(7);
            $latestToken = $user->tokens()->latest()->first();
            if ($latestToken) {
                $latestToken->update(['expires_at' => $expiresAt]);
            }

            return response()->json([
                'user' => $user,
                'token' => [
                    'accessToken' => $latestToken,
                    'plainTextToken' => $token->plainTextToken,
                ]
            ]);

        } catch (\Exception $e) {
            return response()->json(['error' => 'Authentication failed'], 401);
        }
    }

    public function enableTwoFa(Request $request)
    {
        $user = Auth::user();

        // Validate the current password
        $request->validate([
            'password' => 'required',
        ]);

        if (!Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid password'], 403);
        }

        // Check if 2FA is already confirmed
        if ($user->two_factor_secret && $user->two_factor_confirmed_at) {
            return response()->json(['message' => '2FA already enabled'], 400);
        }

        // Generate a new secret key and recovery codes
        $google2fa = new Google2FA();
        $secretKey = $google2fa->generateSecretKey();

        $user->two_factor_secret = encrypt($secretKey);
        $user->two_factor_recovery_codes = encrypt(json_encode([
            Str::random(10) . '-' . Str::random(10),
            Str::random(10) . '-' . Str::random(10),
        ]));
        $user->two_factor_confirmed_at = null; // Reset confirmation status
        $user->save();

        // Return the secret key and QR code URL
        return response()->json([
            'secret' => $secretKey,
            'qr_url' => "otpauth://totp/example-app?secret={$secretKey}&issuer={$user->email}"
        ]);
    }

    public function verifyTwoFa(Request $request){
        $request->validate([
            'code' => 'required|numeric',
        ]);

        $user = Auth::user();
        if (!$user->two_factor_secret) {
            return response()->json(['message' => '2FA not enabled'], 400);
        }

        $google2fa = new Google2FA();
        $isValid = $google2fa->verifyKey(decrypt($user->two_factor_secret), $request->code);

        if (!$isValid) {
            return response()->json(['message' => 'Invalid code'], 403);
        }

        // Generate 8 recovery codes after successful verification
        $recoveryCodes = [];
        for ($i = 0; $i < 8; $i++) {
            $recoveryCodes[] = Str::random(10) . '-' . Str::random(10);
        }

        // Store the recovery codes and mark 2FA as confirmed
        $user->two_factor_recovery_codes = encrypt(json_encode($recoveryCodes));
        $user->two_factor_confirmed_at = now();
        $user->save();

        return response()->json([
            'message' => '2FA verified successfully',
            'recovery_codes' => $recoveryCodes // Return recovery codes to the user
        ]);
    }

    public function showRecoveryCodes()
    {
        $user = Auth::user();

        // Check if 2FA is enabled and recovery codes exist
        if (!$user->two_factor_secret) {
            return response()->json(['message' => '2FA is not enabled'], 400);
        }

        if (!$user->two_factor_recovery_codes) {
            return response()->json(['message' => 'No recovery codes found'], 404);
        }

        // Decrypt and return the recovery codes
        $recoveryCodes = json_decode(decrypt($user->two_factor_recovery_codes), true);

        return response()->json([
            'recovery_codes' => $recoveryCodes
        ]);
    }

    public function regenerateRecoveryCodes()
    {
        $user = Auth::user();

        // Check if 2FA is enabled
        if (!$user->two_factor_secret) {
            return response()->json(['message' => '2FA is not enabled'], 400);
        }

        // Generate new recovery codes
        $newRecoveryCodes = [];
        for ($i = 0; $i < 8; $i++) {
            $newRecoveryCodes[] = Str::random(10) . '-' . Str::random(10);
        }

        // Save the new recovery codes in the database
        $user->two_factor_recovery_codes = encrypt(json_encode($newRecoveryCodes));
        $user->save();

        // Return the new recovery codes
        return response()->json([
            'message' => 'Recovery codes regenerated successfully',
            'recovery_codes' => $newRecoveryCodes
        ]);
    }


    public function loginWithRecoveryCode(Request $request)
    {
        $user = Auth::user();

        // Decrypt recovery codes
        $codes = json_decode(decrypt($user->two_factor_recovery_codes), true);

        // Check if the provided code is valid
        if (!in_array($request->code, $codes)) {
            return response()->json(['message' => 'Invalid recovery code'], 403);
        }

        // Replace the used recovery code with a new one
        $codes = array_map(function ($code) use ($request) {
            return $code === $request->code ? Str::random(10) . '-' . Str::random(10) : $code;
        }, $codes);

        // Update recovery codes in the database
        $user->two_factor_recovery_codes = encrypt(json_encode($codes));
        $user->save();

        // Generate a login token
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'message' => '2FA bypassed with recovery code',
            'user' => $user,
            'token' => $token,
        ]);
    }

    public function disable2FA()
    {
        $user = Auth::user();

        // Check if 2FA is enabled
        if (!$user->two_factor_secret) {
            return response()->json(['message' => '2FA is not enabled'], 400);
        }

        // Disable 2FA by setting related fields to null
        $user->two_factor_secret = null;
        $user->two_factor_recovery_codes = null;
        $user->two_factor_confirmed_at = null;
        $user->save();

        return response()->json(['message' => '2FA has been disabled successfully']);
    }

    public function sendSMS(Request $request)
    {
        // Validate the input
        $request->validate([
            'email' => 'required|email|exists:users,email', // Ensure the email exists in the database
        ]);

        // Find the user by email
        $user = User::where('email', $request->email)->first();

        if (!$user || !$user->contact_number) {
            return response()->json([
                'success' => false,
                'message' => 'User does not have a contact number.',
            ], 404);
        }

        // Generate OTP and expiry time
        $otp = rand(100000, 999999); // Generate a 6-digit OTP
        $otpExpiresAt = now()->addMinutes(20); // Set expiry time to 20 minutes from now

        // Update the user's OTP and expiry time in the database
        $user->update([
            'email_otp' => $otp,
            'otp_expires_at' => $otpExpiresAt,
        ]);

        // Extract parameters for SMS API
        $apiKey = env('BULK_SMS_API_KEY'); // Your API key
        $msg = "Your OTP code is: $otp. It will expire in 20 minutes."; // OTP message
        $to = $user->contact_number; // User's contact number

        // API URL
        $url = 'https://api.sms.net.bd/sendsms';

        // Prepare the cURL request
        $curl = curl_init();

        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => [
                'api_key' => $apiKey,
                'msg' => $msg,
                'to' => $to,
            ],
        ]);

        // Execute the request
        $response = curl_exec($curl);

        // Handle errors or close cURL
        if (curl_errno($curl)) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to send SMS: ' . curl_error($curl),
            ], 500);
        }

        curl_close($curl);

        // Decode API response (assuming it's JSON)
        $responseData = json_decode($response, true);

        // Handle API response
        if (isset($responseData['error']) && $responseData['error'] == 0) {
            return response()->json([
                'success' => true,
                'message' => 'OTP sent successfully!',
                'data' => [
                    'otp' => $otp, // For testing purposes only; remove in production
                    'expires_at' => $otpExpiresAt,
                ],
            ]);
        } else {
            return response()->json([
                'success' => false,
                'message' => $responseData['msg'] ?? 'Failed to send SMS.',
            ], 400);
        }
    }

    public function accountRecoveryRequest(Request $request)
    {
        // Validate the email input
        $request->validate([
            'email' => 'required|email|exists:users,email', // Ensure email exists in the users table
        ]);

        // Find the user by email
        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'User not found.',
            ], 404);
        }

        // Generate a 6-digit OTP
        $otp = rand(100000, 999999);

        // Set OTP expiry time (20 minutes from now)
        $otpExpiresAt = now()->addMinutes(20);

        // Save the OTP and expiry time in the database
        $user->update([
            'email_otp' => $otp,
            'otp_expires_at' => $otpExpiresAt,
        ]);

        // Send the OTP via email
        try {
            Mail::to($user->email)->send(new AccountRecoveryOtpMail($otp));
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to send OTP email. Please try again.',
            ], 500);
        }

        // Return success response
        return response()->json([
            'success' => true,
            'message' => 'OTP sent successfully to your email.',
        ]);
    }

    public function submitAccountRecoveryRequest(Request $request)
    {
        // Validate the input
        $request->validate([
            'email' => 'required|email|exists:users,email', // Ensure the email exists
            'otp' => 'required|string', // OTP must be provided
        ]);

        // Find the user by email
        $user = User::where('email', $request->email)->first();

        // Check if the user has an existing recovery request
        if ($user->accountRecoveryRequest) {
            return response()->json([
                'success' => false,
                'message' => 'You already have an account recovery request pending.',
            ], 400);
        }

        // Verify the OTP
        if ($user->email_otp !== $request->otp || $user->otp_expires_at < now()) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid or expired OTP.',
            ], 400);
        }

        // Create a new account recovery record
        $accountRecovery = AccountRecovery::create([
            'user_id' => $user->id,
        ]);

        // Return success response
        return response()->json([
            'success' => true,
            'message' => 'Account recovery request submitted successfully.',
            'data' => $accountRecovery,
        ]);
    }

    public function processRecoveryRequest(Request $request)
    {
        // Validate the input
        $request->validate([
            'user_id' => 'required|exists:users,id', // Ensure the user ID exists
        ]);

        // Check if the authenticated user is admin
        $admin = auth()->user();
        if ($admin->email !== 'dipto@gmail.com') {
            return response()->json([
                'success' => false,
                'message' => 'You are not authorized to process recovery requests.',
            ], 403);
        }

        // Find the user by ID
        $user = User::findOrFail($request->user_id);

        // Nullify the 2FA-related columns for the user
        $user->update([
            'two_factor_secret' => null,
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
        ]);

        // Update the account recovery record's approval status to true
        $accountRecovery = AccountRecovery::where('user_id', $user->id)->first();
        if ($accountRecovery) {
            $accountRecovery->update([
                'approve' => true,
            ]);
        }

        // Return success response
        return response()->json([
            'success' => true,
            'message' => 'Account recovery request processed successfully.',
        ]);
    }



}
