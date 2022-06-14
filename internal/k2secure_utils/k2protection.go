package k2secure_utils

const (
	IPBLOCKING = `<!DOCTYPE html>
	<html lang="en">
	<head>
		<script>document.body.innerHTML = '';</script>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>K2 has blocked this access.</title>
		<style>html, body, div, span, h1, a {
			margin: 0;
			padding: 0;
			border: 0;
			font-size: 100%;
			font: inherit;
			vertical-align: baseline
		}
	
		body {
			background: -webkit-radial-gradient(26% 19%, circle, #fff, #f4f7f9);
			background: radial-gradient(circle at 26% 19%, #fff, #f4f7f9);
			display: -webkit-box;
			display: -ms-flexbox;
			display: flex;
			-webkit-box-pack: center;
			-ms-flex-pack: center;
			justify-content: center;
			-webkit-box-align: center;
			-ms-flex-align: center;
			align-items: center;
			-ms-flex-line-pack: center;
			align-content: center;
			width: 100%;
			min-height: 100vh;
			line-height: 1
		}
	
		svg, h1, p {
			display: block
		}
	
		svg {
			margin: 0 auto 4vh
		}
	
		h1 {
			font-family: sans-serif;
			font-weight: 300;
			font-size: 34px;
			color: #e0294a;
			line-height: normal
		}
	
		p {
			font-size: 18px;
			line-height: normal;
			color: #9498A7;
			font-family: sans-serif;
			font-weight: 300
		}
	
		a {
			color: #9498A7
		}
	
		.flex {
			text-align: center
		}</style>
	</head>
	<body>
	<div class="flex"><h1>Ohh !!! K2 has blocked this access.</h1>
		<p>If you are an admin of this domain, check the K2 dashboard for more information else contact the admin of this
			domain.</p><br>
		<p>Your IP :{{ID}}</p></div>
	</body>
	</html>`
	APIBLOCKING = `<!DOCTYPE html>
	<html lang="en">
	<head>
		<script>document.body.innerHTML = '';</script>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>K2 has detected an attack.</title>
		<style>html, body, div, span, h1, a {
			margin: 0;
			padding: 0;
			border: 0;
			font-size: 100%;
			font: inherit;
			vertical-align: baseline
		}
	
		body {
			background: -webkit-radial-gradient(26% 19%, circle, #fff, #f4f7f9);
			background: radial-gradient(circle at 26% 19%, #fff, #f4f7f9);
			display: -webkit-box;
			display: -ms-flexbox;
			display: flex;
			-webkit-box-pack: center;
			-ms-flex-pack: center;
			justify-content: center;
			-webkit-box-align: center;
			-ms-flex-align: center;
			align-items: center;
			-ms-flex-line-pack: center;
			align-content: center;
			width: 100%;
			min-height: 100vh;
			line-height: 1
		}
	
		svg, h1, p {
			display: block
		}
	
		svg {
			margin: 0 auto 4vh
		}
	
		h1 {
			font-family: sans-serif;
			font-weight: 300;
			font-size: 34px;
			color: #e0294a;
			line-height: normal
		}
	
		p {
			font-size: 18px;
			line-height: normal;
			color: #9498A7;
			font-family: sans-serif;
			font-weight: 300
		}
	
		a {
			color: #9498A7
		}
	
		.flex {
			text-align: center
		}</style>
	</head>
	<body>
	<div class="flex"><h1>Ohh !!! K2 has detected an attack.</h1>
		<p>If you are an admin of this domain, check the K2 dashboard for more information else contact the admin of this
			domain.</p><br>
		<p>Incident ID : {{ID}}</p></div>
	</body>
	</html>`
)

func GetApiBlockingPage() string {
	return APIBLOCKING
}

func GetipBlockingPage() string {
	return IPBLOCKING
}
