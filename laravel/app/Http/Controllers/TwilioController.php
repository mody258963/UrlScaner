<?php

namespace App\Http\Controllers;

use App\Services\UrlAnalysisService;
use Illuminate\Http\Request;
use Twilio\TwiML\MessagingResponse;
use Illuminate\Support\Facades\Log;
use Twilio\Rest\Client;
class TwilioController extends Controller
{
    protected $urlAnalysisService;

    public function __construct(ViresTotal $urlAnalysisService)
    {
        $this->urlAnalysisService = $urlAnalysisService;
    }

    public function handleIncomingMessage(Request $request)
    {
        set_time_limit(seconds: 600);

        // Log the entire incoming request for debugging purposes
        Log::info($request->all());
    
        // Extract the message body from the request (assuming it's in the 'Body' key)
        $requestBody = $request->input('Body');
        Log::info("Received message: " . $requestBody);
    
        // Check if the message body is a valid URL
        if (!filter_var($requestBody, FILTER_VALIDATE_URL)) {
            $result = "This is not a valid URL.";
        } else {
            // If it's a valid URL, call the URL analysis service to analyze the URL
            $resultBody = $this->urlAnalysisService->analyzeUrl($requestBody);
    
            // Log the raw result for debugging
            Log::info("Raw result from analyzeUrl: " . $resultBody);
    
            // Use a regular expression to remove HTTP headers and keep only the JSON body
            $jsonPart = preg_replace('/^.*\r?\n\r?\n/s', '', $resultBody);  // Strip out the headers
    
            // Log the extracted JSON part
            Log::info("Extracted JSON: " . $jsonPart);
    
            // Try to decode the extracted JSON
            $decodedResult = json_decode($jsonPart, true);  // Decoding as an associative array
    
            // Check if decoding was successful and if it is an array
            if (json_last_error() === JSON_ERROR_NONE && is_array($decodedResult)) {
                
                 $result = $this->handleThreatAnalysisArray($decodedResult); 
                 $this->sendWhatsAppMessage($request->input('From'),$result);
                 
            } else {
                // Log the decoding error and return an error message
                Log::error("JSON decode error: " . json_last_error_msg());
                Log::error("Failed to decode JSON part: " . $jsonPart);
                $result = "Error decoding the analysis result.";
            }
        }
    
        Log::info(message: "Final result: " . $result);
    
        // Create a Twilio MessagingResponse to reply back
        $response = new MessagingResponse();
        
        $response->message($result)->__tostring();
        Log::info(message: "Massege: " . $response);

        // Return the Twilio response as XML
        return $response;
    }




    private function handleThreatAnalysisArray($data)
{
    Log::info('Handling threat analysis array: ' . json_encode($data));

    // Initialize the summary string
    $summary = "";

    // Check for "Dynamic Analysis (Hybrid)" in the first element of the array
    if (isset($data[0]['original'])) {
        $dynamicAnalysis = $data[0]['original'];

        // Extract key details from dynamic analysis
        $verdict = $dynamicAnalysis['verdict'] ?? 'Unknown verdict';
        $threatLevel = $dynamicAnalysis['threat_level'] ?? 'Unknown threat level';
        $totalProcesses = $dynamicAnalysis['total_processes'] ?? 0;
        $totalNetworkConnections = $dynamicAnalysis['total_network_connections'] ?? 0;
        $totalSignatures = $dynamicAnalysis['total_signatures'] ?? 0;

        // Build the summary for dynamic analysis
        $summary .= "Dynamic Analysis:\n";
        $summary .= "Verdict: $verdict\n";
        $summary .= "Threat Level: $threatLevel\n";
        $summary .= "Total Processes: $totalProcesses\n";
        $summary .= "Total Network Connections: $totalNetworkConnections\n";
        $summary .= "Total Signatures: $totalSignatures\n";

        // Append signature details if available
        if (!empty($dynamicAnalysis['signatures'])) {
            $summary .= "Signatures:\n";
            foreach ($dynamicAnalysis['signatures'] as $signature) {
                $signatureName = $signature['name'] ?? 'Unknown signature';
                $signatureCategory = $signature['category'] ?? 'Unknown category';
                $threatLevelHuman = $signature['threat_level_human'] ?? 'Unknown threat level';
                $summary .= "- $signatureName (Category: $signatureCategory, Threat: $threatLevelHuman)\n";
            }
        }
    } else {
        $summary .= "No dynamic analysis data found.\n";
    }

    // Check for "Static Analysis (VirusTotal)" in the second element of the array
    if (isset($data[1])) {
        $staticAnalysis = $data[1];

        // Extract key details from static analysis
        $maliciousCount = $staticAnalysis['malicious'] ?? 0;
        $suspiciousCount = $staticAnalysis['suspicious'] ?? 0;
        $undetectedCount = $staticAnalysis['undetected'] ?? 0;
        $harmlessCount = $staticAnalysis['harmless'] ?? 0;

        // Append static analysis summary
        $summary .= "\nStatic Analysis (VirusTotal):\n";
        $summary .= "Malicious: $maliciousCount\n";
        $summary .= "Suspicious: $suspiciousCount\n";
        $summary .= "Undetected: $undetectedCount\n";
        $summary .= "Harmless: $harmlessCount\n";
    } else {
        $summary .= "No static analysis data found.";
    }

    Log::info('Final summary generated: ' . $summary);

    return $summary;
}


private function sendWhatsAppMessage($to, $body)
{
    $sid = 'AC81956c1797639e578ee961fbd0367e02';
    $token = '2a0e419b10cef3137758d6813b5a1576';
    $twilio = new Client($sid, $token);

    $fromWhatsAppNumber = 'whatsapp:+14155238886';
   //$to = 'whatsapp:+201115298888';
    Log::info('phone number ' . $to);
    try {
        $message = $twilio->messages->create(
            $to,
            [
                'from' => $fromWhatsAppNumber,
                'body' => $body
            ]
        );
        Log::info("WhatsApp message sent, SID: " . $message->sid);
    } catch (\Exception $e) {
        Log::error("Failed to send WhatsApp message: " . $e->getMessage());
    }
}
}