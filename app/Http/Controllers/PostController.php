<?php

namespace App\Http\Controllers;

use App\Events\PostCreated;
use App\Http\Requests\StorePostRequest;
use App\Http\Requests\UpdatePostRequest;
use App\Models\Post;
use GuzzleHttp\Middleware;
use Illuminate\Http\Request;
use Illuminate\Routing\Controllers\HasMiddleware;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Support\Facades\Storage;

class PostController extends Controller
{
    use AuthorizesRequests;

    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $posts = Post::all()->map(function ($post) {
            return [
                'id' => $post->id,
                'title' => $post->title,
                'body' => $post->body,
                'user_id' => $post->user_id,
                'created_at' => $post->created_at,
                'updated_at' => $post->updated_at,
                'image_url' => $post->image ? asset("storage/{$post->image}") : null, // ✅ Convert to full URL
            ];
        });

        return response()->json([
            'success' => true,
            'posts' => $posts
        ], 200);
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
            'image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:5120',
        ]);

        $imagePath = null;
        if ($request->hasFile('image')) {
            // ✅ Store the uploaded file in `storage/app/public/uploads/`
            $imagePath = $request->file('image')->store('uploads', 'public');
        }

        $post = $request->user()->posts()->create([
            'title' => $fields['title'],
            'body' => $fields['body'],
            'image' => $imagePath,
        ]);

        broadcast(new PostCreated($post))->toOthers();

        return response()->json([
            'success' => true,
            'message' => 'Post created successfully!',
            'post' => [
                'id' => $post->id,
                'title' => $post->title,
                'body' => $post->body,
                'user_id' => $post->user_id,
                'image_url' => $post->image ? asset("storage/{$post->image}") : null,
                'created_at' => $post->created_at,
                'updated_at' => $post->updated_at,
            ]
        ], 201);
    }

    /**
     * Display the specified resource.
     */
    public function show(Post $post)
    {
        return response()->json([
            'success' => true,
            'post' => [
                'id' => $post->id,
                'title' => $post->title,
                'body' => $post->body,
                'user_id' => $post->user_id,
                'created_at' => $post->created_at,
                'updated_at' => $post->updated_at,
                'image_url' => $post->image ? asset("storage/{$post->image}") : null, // ✅ Convert to full URL
            ]
        ], 200);
    }

    /**
     * Update the specified resource in storage.
     */
    // patch request issue: https://laracasts.com/discuss/channels/requests/patch-requests-with-form-data-parameters-are-not-recognized
    public function update(Request $request, Post $post)
    {
        // ✅ Authorization Check: Ensure only the post owner can update
        if ($request->user()->id !== $post->user_id) {
            return response()->json([
                'message' => 'Unauthorized to update this post.'
            ], 403);
        }

        // ✅ Validate input fields, including optional image upload
        $fields = $request->validate([
            'title' => 'required|string|max:255',
            'body' => 'required|string',
            'image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:5120',
        ]);

        // ✅ Check if a new image is uploaded
        if ($request->hasFile('image')) {
            // 🔴 Delete the old image before storing the new one
            if ($post->image) {
                Storage::disk('public')->delete($post->image);
            }

            // ✅ Store new image
            $fields['image'] = $request->file('image')->store('uploads', 'public');
        }

        // ✅ Update the post
        $post->update($fields);

        return response()->json([
            'message' => 'Post updated successfully!',
            'post' => [
                'id' => $post->id,
                'title' => $post->title,
                'body' => $post->body,
                'user_id' => $post->user_id,
                'image_url' => $post->image ? asset("storage/{$post->image}") : null, // ✅ Return full image URL
                'created_at' => $post->created_at,
                'updated_at' => $post->updated_at,
            ]
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

    public function currentUserPosts()
    {
        // Get authenticated user
        $user = auth()->user();

        if (!$user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        // Fetch posts belonging to the authenticated user
        $posts = $user->posts()->latest()->get();

        if ($posts->isEmpty()) {
            return response()->json(['message' => 'No posts found'], 200);
        }

        // Format the response
        $formattedPosts = $posts->map(function ($post) {
            return [
                'id' => $post->id,
                'title' => $post->title,
                'body' => $post->body,
                'user_id' => $post->user_id,
                'created_at' => $post->created_at,
                'updated_at' => $post->updated_at,
                'image_url' => $post->image ? asset("storage/{$post->image}") : null, // Convert image path to full URL
            ];
        });

        return response()->json($formattedPosts);
    }


}
