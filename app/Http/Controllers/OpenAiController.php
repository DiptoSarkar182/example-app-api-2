<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use OpenAI\Laravel\Facades\OpenAI;

class OpenAiController extends Controller
{
    public function chat(Request $request)
    {
        // Validate user input
        $request->validate([
            'message' => 'required|string'
        ]);

        // Call OpenAI API
        $result = OpenAI::chat()->create([
            'model' => 'gpt-4o-mini',
            'messages' => [
                ['role' => 'user', 'content' => $request->input('message')],
            ],
        ]);

        // Return the AI response as JSON
        return response()->json([
            'response' => $result->choices[0]->message->content
        ]);
    }
}
