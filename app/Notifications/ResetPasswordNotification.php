<?php

namespace App\Notifications;

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class ResetPasswordNotification extends ResetPassword
{
    /**
     * Get the reset password notification mail message.
     */
    public function toMail($notifiable)
    {
        $frontendUrl = config('app.frontend_url', 'http://localhost:3000'); // ✅ Define frontend URL
        $resetLink = "{$frontendUrl}/reset-password/{$this->token}?email={$notifiable->email}";

        return (new MailMessage)
            ->subject('Reset Your Password')
            ->greeting('Hello!')
            ->line('You requested a password reset. Click the button below to reset your password. You have 1 hour
            to complete this process.')
            ->action('Reset Password', $resetLink)
            ->line('If you did not request a password reset, no further action is required.');
    }
}
