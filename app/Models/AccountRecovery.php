<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AccountRecovery extends Model
{
    /** @use HasFactory<\Database\Factories\AccountRecoveryFactory> */
    use HasFactory;

    protected $fillable = [
        'user_id',
        'approve',
    ];

    // Cast the 'approve' field as boolean
    protected $casts = [
        'approve' => 'boolean',
    ];

    public function user(){
        return $this->belongsTo(User::class);
    }
}
