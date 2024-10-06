<?php

namespace App\Services;

use GuzzleHttp\Client;

class UrlAnalysisService
{
    protected $client;
    protected $cuckooUrl;
    protected $urlScanApiKey;

    public function __construct()
    {
        $this->client = new Client();
        $this->cuckooUrl = env('CUCKOO_BASE_URL');
        $this->urlScanApiKey = env('URLSCAN_API_KEY');
    }

    // Send URL to Cuckoo for dynamic analysis
    public function analyzeWithCuckoo($url)
    {
        try {
            $response = $this->client->post("{$this->cuckooUrl}/tasks/create/url", [
                'headers' => ["Authorization" => "Bearer S4MPL3"],
                'form_params' => [
                    'url' => $url,
                ]
            ]);
    
            return json_decode($response->getBody()->getContents(), true);
    
        } catch (\Exception $e) {
            // Handle error
            return ['error' => $e->getMessage()];
        }
    }

    // Send URL to URLScan.io for static analysis
    public function analyzeWithUrlScan($url)
    {
        $response = $this->client->post('https://urlscan.io/api/v1/scan/', [
            'headers' => [
                'API-Key' => $this->urlScanApiKey
            ],
            'json' => [
                'url' => $url
            ]
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }

    // Analyze the URL using both services and return combined results
    public function analyzeUrl($url)
    {
        // Perform dynamic analysis with Cuckoo
        $cuckooAnalysis = $this->analyzeWithCuckoo($url);

        // Perform static analysis with URLScan.io
        $urlScanAnalysis = $this->analyzeWithUrlScan($url);

        // Combine and return the results
        $combinedResults = [
            'cuckoo' => $cuckooAnalysis,
            'urlscan' => $urlScanAnalysis,
        ];

        return json_encode($combinedResults);
    }
}