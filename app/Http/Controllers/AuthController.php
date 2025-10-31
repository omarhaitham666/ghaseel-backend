<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Cache;

class AuthController extends Controller
{
    
    public function register(Request $request)
    {
       
        $validator = Validator::make($request->all(), [
            'name' => 'required|min:3|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
            'phone' => 'required|unique:users'
        ], [
            'name.required' => 'اسم المستخدم مطلوب',
            'name.min' => 'اقل عدد من الاحرف ثلاثة احرف',
            'email.required' => 'البريد الالكتروني مطلوب',
            'email.email' => 'صيغة البريد الالكتروني غير صحيحه',
            'email.unique' => 'هذا البريد الالكتروني مستخدم بالفعل',
            'password.required' => 'كلمة المرور مطلوبه',
            'password.min' => 'كلمة المرور يجب ان تكون 6 احرف على الاقل',
            'phone.required' => 'رقم الهاتف مطلوب',
            'phone.unique' => 'هذا الرقم مسجل بالفعل'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'errors' => $validator->errors(),
            ], 422);
        }

        $data = $validator->validated();

       
        $verification_code = rand(100000, 999999);

        
        Cache::put('verification_'.$verification_code, [
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
            'phone' => $data['phone'],
        ], now()->addMinutes(10));

        
        Mail::raw("كود التحقق الخاص بك هو: $verification_code", function ($message) use ($data) {
            $message->to($data['email'])->subject('كود التحقق');
        });

        return response()->json([
            'status' => 'success',
            'message' => 'تم إرسال كود التحقق إلى بريدك الإلكتروني'
        ]);
    }

   
    public function verify(Request $request)
    {
       
        $validator = Validator::make($request->all(), [
            'verification_code' => 'required|digits:6',
        ], [
            'verification_code.required' => 'كود التحقق مطلوب',
            'verification_code.digits' => 'كود التحقق يجب أن يكون 6 أرقام'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'errors' => $validator->errors(),
            ], 422);
        }

        $verification_code = $request->verification_code;

        $cachedData = Cache::get('verification_'.$verification_code);

        if (!$cachedData) {
            return response()->json([
                'status' => 'error',
                'message' => 'كود التحقق غير صحيح أو انتهت صلاحيته'
            ], 422);
        }

        
        $user = User::create([
            'name' => $cachedData['name'],
            'email' => $cachedData['email'],
            'password' => $cachedData['password'],
            'phone' => $cachedData['phone'],
            'email_verified_at' => now(), 
        ]);

       
        Cache::forget('verification_'.$verification_code);

        return response()->json([
            'status' => 'success',
            'message' => 'تم تفعيل الحساب والتسجيل بنجاح'
        ]);
    }

    public function login(Request $request)
{
    // التحقق من المدخلات
    $validator = Validator::make($request->all(), [
        'login' => 'required|string',
        'password' => 'required|string|min:6',
    ], [
        'login.required' => 'يرجى إدخال البريد الإلكتروني أو رقم الهاتف',
        'password.required' => 'يرجى إدخال كلمة المرور',
        'password.min' => 'كلمة المرور يجب أن تكون 6 أحرف على الأقل',
    ]);

    if ($validator->fails()) {
        return response()->json([
            'status' => 'error',
            'errors' => $validator->errors(),
        ], 422);
    }

    $login = $request->login;
    $password = $request->password;

    // تحديد إذا كان الإيميل أو رقم الهاتف
    $fieldType = filter_var($login, FILTER_VALIDATE_EMAIL) ? 'email' : 'phone';

    // البحث عن المستخدم
    $user = User::where($fieldType, $login)->first();

    if (!$user || !Hash::check($password, $user->password)) {
        return response()->json([
            'status' => 'error',
            'message' => 'بيانات الدخول غير صحيحة',
        ], 401);
    }

    // إنشاء access token باستخدام Passport
    $tokenResult = $user->createToken('Personal Access Token');
    $token = $tokenResult->accessToken;
    $tokenExpiration = $tokenResult->token->expires_at;

    return response()->json([
        'status' => 'success',
        'message' => 'تم تسجيل الدخول بنجاح',
        'token' => $token,
        'token_type' => 'Bearer',
        'expires_at' => $tokenExpiration,
        'user' => $user,
    ]);
}


public function logout(Request $request)
{
    // الحصول على المستخدم الحالي
    $user = $request->user();

    // التأكد إن فيه توكن مستخدم
    if ($user && $user->token()) {
        $user->token()->revoke();

        return response()->json([
            'status' => 'success',
            'message' => 'تم تسجيل الخروج بنجاح'
        ]);
    }

    return response()->json([
        'status' => 'error',
        'message' => 'المستخدم غير مسجل الدخول أو لا يوجد توكن صالح'
    ], 401);
}


}