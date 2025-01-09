<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request)
    {

        Log::info('Registration attempt with data:', $request->all());

        try {
            $validatedData = $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:1',
            ]);

            $user = User::create([
                'name' => $validatedData['name'],
                'email' => $validatedData['email'],
                'password' => Hash::make($validatedData['password'])
            ]);

            Log::info('User created successfully:', ['user_id' => $user->id]);

            return response()->json([
                'message' => 'Registration successful',
                'user' => $user
            ], 201);

        } catch (\Exception $e) {
            Log::error('Registration error: ' . $e->getMessage());

            return response()->json([
                'message' => 'Registration failed',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function login(Request $request)
    {
        Log::info('Login attempt for email: ' . $request->email);

        try {
            $credentials = $request->validate([
                'email' => 'required|email',
                'password' => 'required'
            ]);


            $user = User::where('email', $credentials['email'])->first();

            if (!$user) {
                Log::warning('Login failed - user not found: ' . $request->email);
                return response()->json([
                    'message' => 'User not found'
                ], 401);
            }


            if (!Hash::check($credentials['password'], $user->password)) {
                Log::warning('Login failed - invalid password for: ' . $request->email);
                return response()->json([
                    'message' => 'Invalid password'
                ], 401);
            }


            Auth::login($user);
            Log::info('Login successful for user: ' . $user->email);

            return response()->json([
                'message' => 'Login successful',
                'user' => $user
            ]);

        } catch (\Exception $e) {
            Log::error('Login error: ' . $e->getMessage());

            return response()->json([
                'message' => 'Login error: ' . $e->getMessage()
            ], 500);
        }
    }
}