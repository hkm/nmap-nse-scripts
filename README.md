nmap-nse-scripts
================


<h3>trane-info.nse</h3>

Trane Tracer SC is an intelligent field panel for communicating with HVAC equipment controllers. Contents of specific directories on the Tracer SC are exposed with the web server application to unauthenticated users. This script obtains information about the installed devices.

<img src=http://www.hakim.ws/img/trane-info.png />


<h3>philipshue-info.nse</h3>

The Philips Hue is a wireless lighting system. This script obtains information from the web API of the Philips Hue Bridge. 

<img src=http://www.hakim.ws/img/philipshue-info.png />


<h3>wemo-switch.nse</h3>
   
The Belkin Wemo Switch is a network enabled power outlet. This scripts changes the switch state (ON/OFF) acording to the argument BinaryState.

Blog: http://websec.ca/blog/view/Belkin-Wemo-Switch-NMap-Scripts

Video: https://www.youtube.com/embed/gfsV7Sh0EgI

<img src=http://www.hakim.ws/img/wemo-switch.png />
   
   
<h3>wemo-info.nse</h3>

The Belkin Wemo Switch is a network enabled power outlet. This scripts obtains information from Belkin Wemo Switch including nearby wireless networks and the current switch state (ON/OFF).

Blog: http://websec.ca/blog/view/Belkin-Wemo-Switch-NMap-Scripts

<img src=http://www.hakim.ws/img/wemo-info.png />


<h3>http-wordpress-attachment.nse</h3>
   
Enumerates URLs of uploaded media and pages in Wordpress blog/CMS installations by exploiting an information disclosure vulnerability.

Original advisory: http://blog.whitehatsec.com/information-leakage-in-wordpress/#.Ueig9m0_yms
   

<h3>httpframe.nse</h3>

Stores the results of an HTTP(S) scan on a HTML page with JQuery. Shows IP, header, realm and tries to identify if target is a router, camera or common web server.

Almacena los resultados de un barrido HTTP(S) en una página web con Frames y JQuery. Muestra las direcciones IP, un mirror del contenido html, el contenido de la cabecera
www-authenticate. De acuerdo al header server o al contenido de la página que obtiene muestra si es un router, cámara o servidor común.
