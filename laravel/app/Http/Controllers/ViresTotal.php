<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use GuzzleHttp\Client;

class ViresTotal extends Controller
{
    private $baseUrl = 'https://www.hybrid-analysis.com/api/v2';
    public function analyzeUrlViresTotal($url)
    {
        set_time_limit(seconds: 600);

        // Get the URL from the request

    
        // Retrieve your VirusTotal API key from the .env file
        $apiKey = env('VIRUSTOTAL_API_KEY');
    
        // Create a new HTTP client
        $client = new Client();
    
        // Step 1: Submit the URL for analysis
        try {
                    
            $submissionResponse = $client->request('POST', $this->baseUrl . '/submit/url', [
                'form_params' => [
                    'url' => $url,
                    'environment_id' => 120 , 
                    'custom_run_time' => 360
                ],
                'headers' => [
                    'accept' => 'application/json',
                    'content-type' => 'application/x-www-form-urlencoded',
                    'x-apikey' => $apiKey,
                ],
            ]);

            if (!isset($submissionResponse['job_id'])) {
                return response()->json(['error' => 'Failed to submit URL for analysis'], 400);
            }
    
            $reportId = $submissionResponse['job_id'];

            $StatusResponse = $client->request('GET', $this->baseUrl . "/report/{$reportId}/state", [
                'headers' => [
                    'accept' => 'application/json',
                    'content-type' => 'application/x-www-form-urlencoded',
                    'x-apikey' => $apiKey,
                ],

            ]);

            if ( $StatusResponse['state'] == 'ERROR' ) {
                return response()->json(['error' => 'Failed to submit URL for analysis'], 400);
            }


    
            // Check if the response contains an analysis ID
            if ($StatusResponse['state'] == 'SUCCESS') {
    
                // Step 2: Use the analysis ID to retrieve the analysis result
                $resultResponse = $client->request('GET', $this->baseUrl . "/report/{$reportId}/summary". $analysisId, [
                    'headers' => [
                        'x-apikey' => $apiKey,
                        'accept' => 'application/json'
                    ]
                ]);
    
                 sleep(60);
                // Decode the response from VirusTotal
                $resultBody = json_decode($resultResponse->getBody(), true);
    
                // Return the result to the user
                return response()->json($resultBody['data']['attributes']['stats']);
            } else {
                return response()->json(['error' => 'Failed to get analysis ID'], 400);
            }
    
        } catch (\Exception $e) {
            // Handle any errors that occur during the API request
            return response()->json(['error' => 'Failed to analyze the URL', 'message' => $e->getMessage()], 500);
        }
    }


 
    public function HybridAnalysisScanUrl($url)
    {

        set_time_limit(seconds: 600);

        // Validate the URL

        // Get the URL to scan

        // Get your API key from .env file
        $apiKey = env('HYBRID_ANALYSIS_API_KEY');

        // Create a new Guzzle client
        $client = new Client();

        try {
            // Step 1: Submit the URL to Hybrid Analysis
            $response = $client->request('POST', 'https://hybrid-analysis.com/api/v2/quick-scan/url', [
                'headers' => [
                    'api-key' => $apiKey,
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                'form_params' => [
                    'url' => $url,         // The URL you want to scan
                    'scan_type' => 'all', // Choose scan type
                ],
            ]);

                // Step 2: Fetch the report after some time (sleep for scan to complete)
                    sleep(60); // Wait for the scan to finish, adjust time as needed

      

                // Decode the report response
                $report = json_decode($response->getBody(), true);
                //dd($report);


                $scanners_v2 = $report['scanners_v2'];
                $filteredScanners = [];
        
                foreach ($scanners_v2 as $scanner) {
                    if ($scanner !== null) {
                        $filteredScanners[] = [
                            'name' => $scanner['name'],
                            'status' => $scanner['status'],
                        ];
                    }
                }

                return response()->json([
                    'status' => 'success',
                    'URL Type' => $report['submission_type'],
                    'id' => $report['id'],
                    'report' => $filteredScanners,
                ]);
        

            // If the job_id is not returned
        } catch (\Exception $e) {
            // Handle the error
            return response()->json(['error' => 'An error occurred: ' . $e->getMessage()], 500);
        }
    }
    
    public function analyzeUrl(Request $request)
    {
        //dd(123);
        // Validate the request input
        $validated = $request->validate([
            'url' => 'required|url'
        ]);
    
        if ($validated) {
            // Perform VirusTotal analysis
             $VirusTotal = $this->analyzeUrlViresTotal($request->input('url'));
    
            // Perform Hybrid analysis
            $hybierd = $this->HybridAnalysisScanUrl($request->input('url'));
    
            // Remove 'headers' and 'original' from the VirusTotal result


        
    
            // Return the response as JSON
            return response()->json([
               'Dynamic analysis' => $hybierd,
               'Static analysis' => $VirusTotal
            ]);
        }
    }

    
}
