<?php

namespace App\Http\Controllers;

use App\Mail\VerifyEmailOtpMail;
use Carbon\Carbon;
use Illuminate\Auth\Events\Registered;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
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

    public function login(Request $request){
        $request->validate([
            'email' => 'required|email|exists:users',
            'password' => 'required',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Please verify your email before logging in.'
            ], 403);
        }

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Incorrect credentials'], 401);
        }

        // ✅ Check if user has 2FA enabled
        if ($user->two_factor_secret) {
            return response()->json([
                'success' => true,
                'status' => 200,
                'message' => 'Please provide the OTP.',
            ]);
        }

        // ✅ If no 2FA is enabled, proceed with issuing token
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
                'plainTextToken' => $token->plainTextToken
            ]
        ]);
    }

    public function verifyLoginOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
            'two_factor_code' => 'required|numeric'
        ]);

        $user = User::where('email', $request->email)->first();

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

        return response()->json([
            'user' => $user->makeHidden(['two_factor_secret', 'two_factor_recovery_codes']), // Hide sensitive fields
            'token' => [
                'accessToken' => $latestToken,
                'plainTextToken' => $token->plainTextToken
            ]
        ]);
    }


    public function logout(Request $request){
        $request->user()->currentAccessToken()->delete();
        return [
            'message'=>'Logged out.'
        ];
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


}
