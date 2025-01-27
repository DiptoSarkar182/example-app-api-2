<?php

namespace App\Http\Controllers;

use App\Http\Requests\StorePostRequest;
use App\Http\Requests\UpdatePostRequest;
use App\Models\Post;
use GuzzleHttp\Middleware;
use Illuminate\Http\Request;
use Illuminate\Routing\Controllers\HasMiddleware;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;

class PostController extends Controller
{
    use AuthorizesRequests;

    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        return Post::all();
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        // ✅ Check authorization using PostPolicy@create
        $this->authorize('create', Post::class);

        $fields = $request->validate([
            'title' => 'required|string|max:255',
            'body' => 'required|string',
        ]);

        // Create post for the authenticated user
        $post = $request->user()->posts()->create($fields);

        return response()->json([
            'success' => true,
            'message' => 'Post created successfully!',
            'post' => $post
        ], 201);
    }

    /**
     * Display the specified resource.
     */
    public function show(Post $post)
    {
        return ['post', $post];
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, Post $post)
    {
        if ($request->user()->id !== $post->user_id) {
            return response()->json([
                'message' => 'Unauthorized to update this post.'
            ], 403);
        }

        // Validate input fields
        $fields = $request->validate([
            'title' => 'required|string|max:255',
            'body' => 'required|string',
        ]);

        // Update the post
        $post->update($fields);

        return response()->json([
            'message' => 'Post updated successfully!',
            'post' => $post
        ], 200);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Request $request, Post $post)
    {
        if ($request->user()->id !== $post->user_id) {
            return response()->json([
                'message' => 'Unauthorized to delete this post.'
            ], 403);
        }

        // Delete the post
        $post->delete();

        return response()->json([
            'message' => 'Post deleted successfully.'
        ], 200);
    }
}
