<?php

namespace App\Http\Controllers\api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Validator;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;  // Import Auth to handle authentication

class authController extends Controller
{
    /**
     * User Registration.
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'fname' => 'required|string|max:255',
            'lname' => 'required|string|max:255',
            'gender' => 'required|in:male,female',
            'birthdate' => 'required|date',
            'address' => 'required|string|max:500',
            'contactnum' => 'required|string|max:15',
            'email' => 'required|email|unique:users,email',
            'role' => 'required|in:admin,user',
            'password' => 'required|confirmed|min:6',
            'imgf' => 'nullable|image|mimes:jpeg,png,jpg|max:2048',
            'imgb' => 'nullable|image|mimes:jpeg,png,jpg|max:2048',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'false',
                'message' => 'Validation errors occurred',
                'errors' => $validator->errors(),
            ]);
        }

        try {
            $imageFrontPath = null;
            $imageBackPath = null;

            if ($request->hasFile('imgf')) {
                $imageFrontPath = $request->file('imgf')->store('images', 'public');
            }

            if ($request->hasFile('imgb')) {
                $imageBackPath = $request->file('imgb')->store('images', 'public');
            }

            $user = User::create([
                'fname' => $request->fname,
                'lname' => $request->lname,
                'gender' => $request->gender,
                'birthdate' => $request->birthdate,
                'address' => $request->address,
                'contactnum' => $request->contactnum,
                'email' => $request->email,
                'role' => $request->role,
                'imgf' => $imageFrontPath,
                'imgb' => $imageBackPath,
                'password' => Hash::make($request->password),
            ]);

            return response()->json([
                'status' => 'true',
                'message' => 'User Registered Successfully!',
                'data' => $user->createToken('register_token')->plainTextToken
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'false',
                'message' => 'An error occurred while processing your request',
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * User Login.
     */
    public function login(Request $request)
    {
        // Validate the input
        $credentials = $request->only('email', 'password');
    
        // Attempt to authenticate the user
        if (Auth::attempt($credentials)) {
            $user = Auth::user();
            $token = $user->createToken('login_token')->plainTextToken;
    
            return response()->json([
                'status' => 'true',
                'message' => 'Login successful!',
                'token' => $token,
                'user' => $user,
            ]);
        } else {
            return response()->json([
                'status' => 'false',
                'message' => 'Invalid credentials',
            ], 401);
        }
    }
    
}