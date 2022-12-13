<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Image;
use Symfony\Component\HttpFoundation\Response;

class ImageController extends Controller
{
    public function imageStore(Request $request)
    {
        $this->validate($request, [
            'image' => 'required|image|mimes:jpg,png,jpeg,gif,svg|max:2048',
        ]);
        $image_path = $request->file('image')->store('image', 'public');

        $data = Image::create([
            'image' => $image_path,
        ]);

        return response($data, Response::HTTP_CREATED);
    }
}
