<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('account_recoveries', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->default("")->constrained()->onDelete('cascade');
            $table->boolean('approve')->default(false);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('account_recoveries');
    }
};
