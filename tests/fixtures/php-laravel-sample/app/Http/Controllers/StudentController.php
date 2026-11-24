<?php
namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class StudentController
{
    public function search($email)
    {
        return DB::table('students')->whereRaw("email = '$email'")->get();
    }
}
