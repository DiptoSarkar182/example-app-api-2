<?php

use App\Http\Controllers\OpenAiController;
use App\Http\Controllers\PostController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

//Route::get('/user', function (Request $request) {
//    return $request->user();
//})->middleware('auth:sanctum');

// OTP verification routes
Route::post('verify-otp', [AuthController::class, 'verifyOtp']);
Route::post('resend-otp', [AuthController::class, 'resendOtp'])
    ->middleware('throttle:6,1'); // Limit resend attempts

// Public routes (accessible without authentication)
Route::apiResource('posts', PostController::class)->only(['index', 'show']);

// Protected routes (require Sanctum authentication)
Route::middleware('auth:sanctum')->group(function () {
    Route::apiResource('posts', PostController::class)->only(['store', 'update', 'destroy']);
    Route::get('current-user-posts', [PostController::class, 'currentUserPosts']);
});

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::post('/logout', [AuthController::class, 'logout'])->middleware('auth:sanctum');
Route::post('/verify-login-otp', [AuthController::class, 'verifyLoginOtp']);
Route::get('/current-user-sessions', [AuthController::class, 'currentUserSessions'])
    ->middleware('auth:sanctum');

// update user info
Route::middleware('auth:sanctum')->group(function () {
    Route::patch('update-user-info', [AuthController::class, 'updateUserInfo']);
});

// current user password update
Route::middleware('auth:sanctum')->group(function () {
    Route::patch('update-password', [AuthController::class, 'updateUserPassword']);
});

Route::post('send-reset-password-instruction', [AuthController::class, 'sendResetPasswordInstruction']);
Route::post('complete-reset-password', [AuthController::class, 'completeResetPassword']);

//google sign in
Route::get('/auth/google/redirect', [AuthController::class, 'redirectToGoogle']);
Route::get('/auth/google/callback', [AuthController::class, 'handleGoogleCallback']);

//openai route
Route::post('/openai/chat', [OpenAiController::class, 'chat'])->middleware('auth:sanctum');

//2fa-route
Route::get('/show-recovery-codes', [AuthController::class, 'showRecoveryCodes'])
    ->middleware('auth:sanctum');
Route::post('/enable-2fa', [AuthController::class, 'enableTwoFa'])->middleware('auth:sanctum');
Route::post('/verify-2fa', [AuthController::class, 'verifyTwoFa'])->middleware('auth:sanctum');
Route::post('/login-with-recovery-code', [AuthController::class, 'loginWithRecoveryCode'])
    ->middleware('auth:sanctum');
Route::post('/regenerate-recovery-code', [AuthController::class, 'regenerateRecoveryCodes'])
    ->middleware('auth:sanctum');
Route::post('/disable-2FA', [AuthController::class, 'disable2FA'])
    ->middleware('auth:sanctum');
Route::post('/send-sms', [AuthController::class, 'sendSMS'])
    ->middleware('auth:sanctum');

Route::post('/send-account-recovery-request', [AuthController::class, 'accountRecoveryRequest']);
Route::post('/submit-account-recovery-request', [AuthController::class, 'submitAccountRecoveryRequest']);
Route::post('/process-account-recovery-request', [AuthController::class, 'processRecoveryRequest'])
    ->middleware('auth:sanctum');


