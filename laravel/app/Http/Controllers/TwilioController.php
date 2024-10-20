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
            $result = "نقوم بتحليل ، الرابط الرجاء الانتظار. قليلاً";
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
                
                $result = 'نقوم بتحليل ، الرابط الرجاء الانتظار. قليلاً';
                 $resultEnd = $this->handleThreatAnalysisArray($decodedResult); 

               foreach ($resultEnd as $messagePart) {
            $this->sendWhatsAppMessage($request->input('From'), $messagePart);
            sleep(1);  // Delay to avoid rapid consecutive messages (optional)
        }
                 
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
    
        // Initialize an array to hold the message parts
        $summaryParts = [];
    
        // Check for "Dynamic Analysis (Hybrid)" in the first element of the array
        if (isset($data[0]['original'])) {
            $dynamicAnalysis = $data[0]['original'];
    
            // Extract key details from dynamic analysis
            $classificationTags = $dynamicAnalysis['classification_tags'] ?? [];
            $verdict = $dynamicAnalysis['verdict'] ?? 'Unknown verdict';
            $threatScore = $dynamicAnalysis['threat_score'] ?? 0;
            $totalProcesses = $dynamicAnalysis['total_processes'] ?? 0;
            $totalNetworkConnections = $dynamicAnalysis['total_network_connections'] ?? 0;
            $totalSignatures = $dynamicAnalysis['total_signatures'] ?? 0;
            $avDetect = $dynamicAnalysis['AV_detect'];
    
            // Break the message into parts and push them into the array
            $summaryParts[] = "شكرا للإنتظار لقد قمنا بتحليل الرابط الذي أرسلته\n";
            
                        if (is_array($classificationTags)) {
                           $name =  "التصنيف: " . implode(', ', $classificationTags) . "\n";
                        }
            
            $summaryParts[] = "نوع التحليل:\n" .
                "تحليل ثابت: تم فحص الرمز والعناصر المكونة للرابط للتحقق من أي إشارات مشبوهة.\n" .
                "تحليل ديناميكي: تم اختبار الرابط في بيئة آمنة لمراقبة سلوكه عند الوصول إليه.\n" .
                "بيئة الاختبار: Windows 10 64-bit.\n" .
                "____________________________________________________________________________\n" .
                "الحكم النهائي: $verdict\n" .
                "درجة التهديد: $threatScore%\n" . 
                $name ;


    
            $summaryParts[] = "للمزيد من التفاصيل\n" .  " $avDetect من  برامج مضادة للفيروسات اكتشفت اشتباه تهديد.\n" .
                "تم العثور على $totalSignatures توقيعًا يحتمل أن يكون تهديدًا.\n" .
                "تم العثور على $totalNetworkConnections اتصالًا بالشبكة.\n" .
                "تم العثور على $totalProcesses عملية تم تشغيلها أثناء التحليل الديناميكي.\n";
    
            // Append signature details if available
            if (!empty($dynamicAnalysis['signatures'])) {
                $signatureDetails = "كانت العمليات  المشبوه على النحو  التالي:\n";
                foreach ($dynamicAnalysis['signatures'] as $signature) {
                    $signatureName = $signature['name'] ?? 'Unknown signature';
                    $signatureDetails .= "$signatureName\n";
                }
                $summaryParts[] = $signatureDetails;
            }
        } else {
            $summaryParts[] = "No dynamic analysis data found.\n";
        }
    
        // Additional advice and security recommendations
        $summaryParts[] = "نوصي بشدة باتخاذ التدابير الوقائية التالية:\n" .
            "1. عدم النقر على الروابط غير الموثوقة.\n" .
            "2. تحديث برامج الحماية بانتظام.\n" .
            "3. تجنب تنزيل الملفات غير الموثوقة.\n" .
            "4. فحص الروابط قبل فتحها.\n" .
            "5. تجاهل الرسائل التي تطلب معلومات شخصية أو مالية بشكل غير عادي.\n" .
            "6. إنشاء نسخ احتياطية من بيانات هاتفك بانتظام.\n" .
            "اتباع هذه الخطوات يمكن أن يساعد في حماية معلوماتك الشخصية من التهديدات الإلكترونية.\n";
    
        Log::info('Final message parts generated: ' . json_encode($summaryParts));
    
        // Return the array of message parts
        return $summaryParts;
    }
    
    
private function sendWhatsAppMessage($to, $body)
{
    $sid = 'AC81956c1797639e578ee961fbd0367e02';
    $token = '647abf2c73a31a9ef99c8a8c94416ffa';
    $twilio = new Client($sid, $token);

    $fromWhatsAppNumber = 'whatsapp:+14155238886';
   //$to = 'whatsapp:+201115298888';
    Log::info('phone number ' . $to);
    try {
        $twilio->setSslVerification(false);
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