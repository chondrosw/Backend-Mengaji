<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;

use Throwable;

class UserController extends Controller
{
    //
    public function register(Request $request){
        try{
            $request->validate([
                'name' => ['required','string','max:255'],
                'date' => ['required','string','max:255'],
                'username' => ['required','string','max:255','unique:users'],
                'password' => ['required','string',new Password]
            ]);

            User::create([
                'name' => $request->name,
                'date' => $request->date,
                'username' => $request->username,
                'password' => Hash::make($request->password)

            ]);
            $user = User::where('username', $request->username)->first();
            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponsesFormatter::success([
                'accessToken' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ],'User Registered');
        }catch(Exception $e){
            return ResponsesFormatter::error([
                'message' => 'Something went wrong',
                'error' => $e
            ],'Authentication Failed',500);
        }
    }

    public function login(Request $request){
        try{
            $request->validate([
                'username' => 'string|required',
                'password' => 'required'
            ]);

            $credentials = request(['username','password']);
            if(!Auth::attempt($credentials)){
                return ResponsesFormatter::error([
                    'message' => 'Unauthorized. Please',
                ],'Authentication Failed',500);
            }
            $user = User::where('username',$request->username)->first();
            if(!Hash::check($request->password,$user->password,[])){
                return ResponsesFormatter::error([
                    'message' => 'Your password is incorrect',
                ],'Your password is incorrect',500);
            }
            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponsesFormatter::success([
                'accessToken' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ],'Authenticated');
        }catch(Exception $e){
            return ResponsesFormatter::error([
                'message' => 'Something went wrong',
                'error' => $e
            ],'Authenticated Failed',500);
        }
    }
}
