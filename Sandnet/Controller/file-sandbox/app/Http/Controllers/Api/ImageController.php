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

        try{
            $apiKey = '30557d15b2e2f8cf46a81751b287b28c9e0570dc89edc6a061df09ef14ed92ad';

            // Scan file
            $fileScanner = new \Monaz\VirusTotal\File($apiKey);
            $resp = $fileScanner->scan($request->file('image'));
            $result = $fileScanner->getReport($resp['hash']);
    
            if($result['attributes']['last_analysis_stats']['malicious'] == 0){
                $image_path = $request->file('image')->store('public');
                $image_path = ltrim($image_path, 'public/');
                $storage_path = "storage/" . $image_path;  
    
                $data = Image::create([
                    'image' => $storage_path,
                ]);
                return response($data, Response::HTTP_CREATED);  
            }else{
                return "{'title':'Warning', 'body':'File is unsafe'}";
            }
        }catch(\Exception $e){
            return "Something wrong !!!";
        }
    }
}
