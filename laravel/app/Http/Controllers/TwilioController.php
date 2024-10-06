<?php

namespace App\Http\Controllers;

use App\Services\UrlAnalysisService;
use Illuminate\Http\Request;
use Twilio\TwiML\MessagingResponse;

class TwilioController extends Controller
{
    protected $urlAnalysisService;

    public function __construct(UrlAnalysisService $urlAnalysisService)
    {
        $this->urlAnalysisService = $urlAnalysisService;
    }

    public function handleIncomingMessage(Request $request)
    {
        // Extract the URL sent via WhatsApp
        $userMessage = $request->input('Body');

        // Send URL for analysis (integrating both Cuckoo and URLScan.io)
        $analysisResult = $this->urlAnalysisService->analyzeUrl($userMessage);

        // Send response back to WhatsApp via Twilio
        $response = new MessagingResponse();
        $response->message("URL Analysis Report: " . $analysisResult);

        return response($response)->header('Content-Type', 'text/xml');
    }
}