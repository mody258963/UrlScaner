<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use GuzzleHttp\Client;

class ViresTotal extends Controller
{
    private $baseUrlHybired = 'https://www.hybrid-analysis.com/api/v2';
    private $baseUrl;

    // Analyze URL using VirusTotal
    public function analyzeUrlVirusTotal($url)
    {
        // Extend the script execution time to handle long requests
        set_time_limit(600);
    
        // Retrieve your VirusTotal API key from the .env file
        $apiKey = env('VIRUSTOTAL_API_KEY');
        $client = new Client();
        $this->baseUrl = 'https://www.virustotal.com/api/v3'; // VirusTotal API v3
    
        try {
            // Submit URL for analysis
            $submissionResponse = $client->request('POST', $this->baseUrl . '/urls', [
                'headers' => [
                    'x-apikey' => $apiKey,
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                'form_params' => [
                    'url' => $url,
                ],
            ]);
    
            $submissionBody = json_decode($submissionResponse->getBody(), true);
    
            if (!isset($submissionBody['data']['id'])) {
                return response()->json(['error' => 'Failed to submit URL for analysis'], 400);
            }
    
            $reportId = $submissionBody['data']['id'];
    
            // Poll the analysis state until it's completed
            do {
                $statusResponse = $client->request('GET', $this->baseUrl . "/analyses/{$reportId}", [
                    'headers' => [
                        'x-apikey' => $apiKey,
                        'accept' => 'application/json',
                    ],
                ]);
    
                $statusBody = json_decode($statusResponse->getBody(), true);
    
                if (isset($statusBody['error'])) {
                    return response()->json(['error' => 'Failed to retrieve analysis state'], 400);
                }
    
                $state = $statusBody['data']['attributes']['status'];
    
                sleep(10);
    
            } while ($state != 'completed'); // Repeat until the analysis is completed
    
            // Retrieve the analysis result
            $resultResponse = $client->request('GET', $this->baseUrl . "/analyses/{$reportId}", [
                'headers' => [
                    'x-apikey' => $apiKey,
                    'accept' => 'application/json',
                ]
            ]);
    
            $resultBody = json_decode($resultResponse->getBody(), true);
    
            return $resultBody['data']['attributes']['stats']; // Return result directly for further processing
    
        } catch (\Exception $e) {
            return ['error' => 'Failed to analyze the URL', 'message' => $e->getMessage()];
        }
    }

    // Analyze URL using Hybrid Analysis
    public function HybridAnalysisScanUrl($url)
    {
        //set_time_limit(600);
        $apiKey = env('HYBRID_ANALYSIS_API_KEY');
        $client = new Client();
    
        try {
            // Submit URL for analysis
            $submissionResponse = $client->request('POST', $this->baseUrlHybired . '/submit/url', [
                'form_params' => [
                    'url' => $url,
                    'environment_id' => 160, 
                    'custom_run_time' => 360
                ],
                'headers' => [
                    'accept' => 'application/json',
                    'content-type' => 'application/x-www-form-urlencoded',
                    'api-key' => $apiKey,
                ],
            ]);
            
            // sleep(120);
            $submissionBody = json_decode($submissionResponse->getBody(), true);
            
            if (!isset($submissionBody['job_id'])) {
                return ['error' => 'Failed to submit URL for analysis'];
            }
            
            $reportId = $submissionBody['job_id'];
            if ($submissionResponse){
                do {
                    $statusResponse = $client->request('GET', $this->baseUrlHybired . "/report/{$reportId}/state", [
                        'headers' => [
                            'accept' => 'application/json', 
                            'content-type' => 'application/x-www-form-urlencoded',
                            'api-key' => $apiKey,
                        ],
                    ]);
                    
                    $statusBody = json_decode($statusResponse->getBody(), true);
                    
                    if (isset($statusBody['error']) || $statusBody['state'] == 'ERROR') {
                        return ['error' => 'Failed to retrieve analysis state'];
                    }
                    
                    $state = $statusBody['state'];
                    
                    
                    
                } while ($state != 'SUCCESS');
                
            }
            
            // Retrieve the analysis result
            $resultResponse = $client->request('GET', $this->baseUrlHybired . "/report/{$reportId}/summary", [
                'headers' => [
                    'api-key' => $apiKey,
                    'accept' => 'application/json',
                    ]
                ]);
                
                $resultBody = json_decode($resultResponse->getBody(), true);
                $responseArray = [
                    'job_id' => $resultBody['job_id'],
                    'classification_tags' => $resultBody['classification_tags'],
                    'tags' => $resultBody['tags'],
                    'environment_description' => $resultBody['environment_description'],
                    'threat_level' => $resultBody['threat_level'],
                    'AV_detect' => $resultBody['av_detect'],
                    'VX_family' => $resultBody['vx_family'],
                    'threat_score' => $resultBody['threat_score'],
                    'verdict' => $resultBody['verdict'],
                    'total_network_connections' => $resultBody['total_network_connections'],
                    'total_processes' => $resultBody['total_processes'],
                    'total_signatures' => $resultBody['total_signatures']
                ];
    
                // 5. Add signatures to the response array
                foreach ($resultBody['signatures'] as $signature) {
                    if (isset($signature['threat_level_human']) && isset($signature['name'])) {
                        // Exclude signatures where 'threat_level_human' is 'informative'
                        if ($signature['threat_level_human'] !== "informative") {
                            $responseArray['signatures'][] = [
                                'threat_level_human' => $signature['threat_level_human'],
                                'name' => $signature['name'],
                            ];
                        }
                    }
                }
                
                // Return the final JSON response
                return response()->json($responseArray);
    
                
            } catch (\Exception $e) {
            return ['error' => 'Failed to analyze the URL', 'message' => $e->getMessage()];
        }
    }

    // Main function to analyze the URL with both VirusTotal and Hybrid Analysis
    public function analyzeUrl(Request $request)
    {
        $validated = $request->validate(['url' => 'required|url']);
    
        if ($validated) {
            // Perform VirusTotal and Hybrid Analysis
           
            $hybridResult = $this->HybridAnalysisScanUrl($request->input('url'));
           if($hybridResult){
            $virusTotalResult = $this->analyzeUrlVirusTotal($request->input('url'));
           }
            return response()->json([
                'Dynamic Analysis (Hybrid)' => $hybridResult,
                'Static Analysis (VirusTotal)' => $virusTotalResult
            ]);
        }
    }
}
