<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\UrlAnalysisService;
class UrlAnalysisController extends Controller
{
    protected $urlAnalysisService;

    public function __construct( UrlAnalysisService $urlAnalysisService)
    {
        $this->urlAnalysisService = $urlAnalysisService;
    }

    public function analyze(Request $request)
{
   
        // Validate the incoming request
        $request->validate([
            'url' => 'required|url',
        ]);

        // Retrieve the URL from the request
        $url = $request->input('url');

        // Analyze the URL using the service
        $results = $this->urlAnalysisService->analyzeUrl($url);

        // Return the results as a JSON response
        return response()->json($results);
    }
}

