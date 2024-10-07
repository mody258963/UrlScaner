<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use GuzzleHttp\Client;

class ViresTotal extends Controller
{
    public function analyzeUrl(Request $request)
    {
        // Get the URL from the request
        $url = $request->input('url', 'https://majdsoft.000webhostapp.com/pages/index.php'); // default URL for testing
    
        // Retrieve your VirusTotal API key from the .env file
        $apiKey = env('VIRUSTOTAL_API_KEY');
    
        // Create a new HTTP client
        $client = new Client();
    
        // Step 1: Submit the URL for analysis
        try {
            $response = $client->request('POST', 'https://www.virustotal.com/api/v3/urls', [
                'form_params' => [
                    'url' => $url
                ],
                'headers' => [
                    'accept' => 'application/json',
                    'content-type' => 'application/x-www-form-urlencoded',
                    'x-apikey' => $apiKey,
                ],
            ]);
    
            $body = json_decode($response->getBody(), true);
    
            // Check if the response contains an analysis ID
            if (isset($body['data']['id'])) {
                $analysisId = $body['data']['id'];
    
                // Step 2: Use the analysis ID to retrieve the analysis result
                $resultResponse = $client->request('GET', 'https://www.virustotal.com/api/v3/analyses/' . $analysisId, [
                    'headers' => [
                        'x-apikey' => $apiKey,
                        'accept' => 'application/json'
                    ]
                ]);
    
                // Decode the response from VirusTotal
                $resultBody = json_decode($resultResponse->getBody(), true);
    
                // Return the result to the user
                return response()->json($resultBody);
            } else {
                return response()->json(['error' => 'Failed to get analysis ID'], 400);
            }
    
        } catch (\Exception $e) {
            // Handle any errors that occur during the API request
            return response()->json(['error' => 'Failed to analyze the URL', 'message' => $e->getMessage()], 500);
        }
    }

    public function analyzeUrlBehavior(Request $request)
    {
        // Get the URL from the request
        $url = $request->input('url', 'https://majdsoft.000webhostapp.com/pages/index.php'); // default URL for testing

        // Retrieve your VirusTotal API key from the .env file
        $apiKey = env('VIRUSTOTAL_API_KEY');

        // Create a new HTTP client
        $client = new Client();

        try {
            // Step 1: Submit the URL to VirusTotal for analysis (URL is base64 encoded)
            $encodedUrl = rtrim(strtr(base64_encode($url), '+/', '-_'), '=');

            $response = $client->request('POST', 'https://www.virustotal.com/api/v3/urls', [
                'form_params' => [
                    'url' => $url
                ],
                'headers' => [
                    'accept' => 'application/json',
                    'content-type' => 'application/x-www-form-urlencoded',
                    'x-apikey' => $apiKey,
                ],
            ]);

            // Decode the response to get the analysis ID
            $body = json_decode($response->getBody(), true);

            if (isset($body['data']['id'])) {
                $analysisId = $body['data']['id'];

                // Step 2: Retrieve the behavior analysis report using the analysis ID
                $reportResponse = $client->request('GET', 'https://www.virustotal.com/api/v3/analyses/' . $analysisId, [
                    'headers' => [
                        'x-apikey' => $apiKey,
                        'accept' => 'application/json'
                    ]
                ]);

                // Decode the behavior analysis report
                $reportBody = json_decode($reportResponse->getBody(), true);

                // Return the detailed behavior report as JSON
                return response()->json($reportBody);
            } else {
                return response()->json(['error' => 'Failed to get analysis ID'], 400);
            }

        } catch (\Exception $e) {
            // Handle any errors that occur during the API request
            return response()->json(['error' => 'Failed to analyze URL behavior', 'message' => $e->getMessage()], 500);
        }
    }
    
}
