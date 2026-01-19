def email():
    return {
        "template": """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SOC DAILY REPORT</title>
  <style>
      @font-face {
      font-family: 'Lato';
      font-style: normal;
      font-weight: 400;
      src: local('Lato Regular'), local('Lato-Regular'),
        url('https://fonts.gstatic.com/s/lato/v23/S6uyw4BMUTPHjxAwXiWtFCc.woff2') format('woff2');
    }
    

    body {
      margin: 0;
      padding: 0;
      background-color: #f4f6f8;
      font-family: 'Lato', 'Segoe UI', sans-serif;
    }

    img {
      display: block;
      max-width: 100%;
      height: auto;
    }

    table {
      border-spacing: 0;
      border-collapse: collapse;
    }

    @media only screen and (max-width: 620px) {
      .wrapper {
        width: 100% !important;
        padding: 0 10px !important;
      }

      .inner-padding {
        padding: 20px 15px !important;
      }

      .column {
        display: block;
        width: auto !important;
        margin-bottom: 5px;
      }

      .cta-button {
        display: block;
        width: 100% !important;
        text-align: center !important;
        padding: 12px 0 !important;
      }
    }
  </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f6f8; font-family: 'Lato', 'Segoe UI', sans-serif;">

  <table width="100%" cellpadding="0" cellspacing="0" style="padding: 40px 0; margin-top: 20px;">
    <tr>
      <td align="center">
        <table class="wrapper" width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 10px; overflow: hidden; box-shadow: 0 0 8px rgba(0, 0, 0, 0.05);">
          
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(117.87deg, #090B19 42.87%, #102A47 99.67%); color: #ffffff; text-align: center; padding: 30px 20px;">
              <img src="https://binaryflux.ai/images/logo.png" alt="Binaryflux Logo" style="height: 35px; margin: auto;">
              <h2 style="margin: 10px 0 0; font-size: 22px;font-family: 'Lato', 'Segoe UI', sans-serif;"> SOC DAILY REPORT</h2>
              <p style="margin: 8px 0 0; font-size: 14px;font-family: 'Lato', 'Segoe UI', sans-serif;">A Comprehensive Analysis Of Security Events</p>
            </td>
          </tr>

          <!-- Full Email Body -->
            <tr>
            <td class="inner-padding" style="padding: 0 24px 20px;">
                <div style="padding: 20px; background-color: #f1f3f4; border-radius: 6px;">
                <p style="font-family: 'Lato', 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; margin: 0 0 16px;">
                    <strong>Hi</strong>,
                </p>
                <p style="font-family: 'Lato', 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; margin: 0 0 16px;">
                    We are pleased to share the latest report with you, which provides valuable insights into the current security landscape, highlights key trends, and outlines performance metrics critical to your organization's risk posture and operational efficiency.
                </p>
                <p style="font-family: 'Lato', 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; margin: 0 0 16px;">
                    You can access the full report by clicking the button below:
                </p>
                <p style="font-family: 'Lato', 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; margin: 0 0 16px;">
                    If you have any questions, require further clarification, or would like to schedule a review meeting, please don’t hesitate to contact our support team.
                </p>
                <p style="font-family: 'Lato', 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; margin: 0 0 16px;">
                    Thank you for your continued trust in our services.
                </p>
                <p style="font-family: 'Lato', 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; margin: 0;">
                    Best regards,<br>
                    Administrator<br>
                </p>
                </div>
            </td>
            </tr>

          <!-- CTA -->
          <tr>
            <td align="center" style="padding: 10px 24px 30px;">
              <a class="cta-button" href="http://${filepath}" target="_blank" style="background-color: #1a73e8; color: #ffffff; padding: 12px 28px; font-size: 15px; border-radius: 6px; text-decoration: none;font-family: 'Lato', 'Segoe UI', sans-serif;">
                View Full SOC Report
              </a>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td align="center" style="background-color: #f5f7fa; color: #6a737d; font-size: 12px; padding: 20px; font-family: 'Lato', 'Segoe UI', sans-serif;">
              &copy; 2025 Binaryflux. All rights reserved.<br>
              <span style="font-size: 11px;font-family: 'Lato', 'Segoe UI', sans-serif;">This is an automated message. Please do not reply.</span>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>

</body>
</html>

            """,
        "subject": "The Daily SOC Report",
    }



def html():
    return  """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>SOC Daily Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
              body {
                font-family: Arial, sans-serif;
                margin: 40px;
                background: #fff;
                color: #333;
                max-width: 1600px;
                background: #f5f7fa;
                /* subtle light grey */
              }
        
              h1 {
                text-align: center;
                color: #2c3e50;
                margin-bottom: 5px;
                font-size: 32px;
                font-weight: 700;
              }
        
              p.subtitle {
                text-align: center;
                margin-bottom: 40px;
                color: #555;
                font-size: 16px;
                color: #6c7a89;
              }
        
              .grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                gap: 40px;
                padding: 0px 20px;
              }
        
              .section {
                border: 1px solid #ddd;
                border-radius: 12px;
                padding: 15px 20px;
                margin-top:20px;
                box-shadow: 0 1px 4px rgba(0, 0, 0, 0.05);
                background: #ffffff;
                page-break-inside: avoid;
                break-inside: avoid;
              }
        
              .section h2 {
                font-size: 16px;
                color: #2c3e50;
                font-size: 18px;
                font-weight: 600;
                border-bottom: 2px solid #eee;
                padding-bottom: 8px;
                margin-bottom: 12px;
              }
        
              .section p {
                font-size: 12px;
                color: #666;
                margin-bottom: 10px;
              }
        
              .kpi-cards {
                display: flex;
                justify-content: space-around;
                text-align: center;
              }
        
              .kpi {
                flex: 1;
                background: #fff;
                border-radius: 6px;
                padding: 20px;
                margin: 5px;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
              }
        
              .kpi h3 {
                margin: 0;
                font-size: 28px;
                color: #2c3e50;
              }
        
              .kpi p {
                margin: 5px 0 0 0;
                font-size: 12px;
                color: #666;
              }
        
              canvas {
                width: 100% !important;
                height: 300px !important;
              }
        
              .chart-container.round-chart {
                width: 300px;
                /* Fix width */
                aspect-ratio: 1/1;
                /* Keep it round */
                margin: 0 auto;
                /* Center it */
              }
        
              .chart-description {
                font-size: 12px;
                color: #aaa;
                margin-top: 10px;
              }
        
              .report-date {
                text-align: right;
                font-size: 12px;
                color: #666;
                margin-bottom: 10px;
              }
              table {
                  font-family: Arial, sans-serif; /* Or any font you prefer */
                  font-size: 12px; /* Adjust as needed */
                  color: #333; /* Text color */
                }

              th, td {
                font-family: inherit; /* Use table's font */
                font-size: inherit;
              }
            </style>

</head>

<body>
  <div class="report-date">Date: ${report_generated_date}</div>
  <h1>SOC Daily Report</h1>
  <p class="subtitle">A comprehensive analysis of security trends, threat detections, anomalies, monitored assets, event criticality, and key performance indicators (KPIs) over the reporting period.</p>

  <div class="grid">

      <div class="section">
                <h2>${event_volume_trends_by_time.title}</h2>
                <p>${event_volume_trends_by_time.description}</p>
                <canvas id="${event_volume_trends_by_time}"></canvas>
                <p class="chart-description"> Shows total security events, tracked hourly for trend analysis. </p>
              </div>
    <div class="section">
                <h2>${detection_volume_trends_by_time.title}</h2>
                <p>${detection_volume_trends_by_time.description}</p>
                <canvas id="${detection_volume_trends_by_time}"></canvas>
                <p class="chart-description"> Shows total detection counts, tracked hourly for trend analysis. </p>
              </div>

            



    <div class="section">
      <h2>${top_recurring_threat_detections.title}</h2>
      <p>${top_recurring_threat_detections.description}</p>
      <canvas id="${top_recurring_threat_detections}"></canvas>
      <p>Shows the most common detection rules and their counts to reveal top recurring threats.</p>
    </div>


      
    
    <div class="section">
      <h2>${top_entities_involved_in_security_events.title}</h2>
      <p>${top_entities_involved_in_security_events.description}</p>
      <canvas id="${top_entities_involved_in_security_events}"></canvas>
      <p>Highlights the top entities linked to events for better risk insight and monitoring.</p>

     <div class="section">
      <h2>${coverage_by_threat_category.title}</h2>
      <p>${coverage_by_threat_category.description}</p>
      <div class="chart-container round-chart">
      <canvas id="${coverage_by_threat_category}"></canvas>
      <p>Shows which tactics are covered by current detections, highlighting coverage across different attack stages.</p>

      </div>
    </div>
    <div class="section">
      <h2>${detection_severity_breakdown.title}</h2>
      <p>${detection_severity_breakdown.description}</p>
      <div class="chart-container round-chart">
      <canvas id="${detection_severity_breakdown}"></canvas>
      <p>This chart breaks down detections by their criticality levels, helping prioritize response efforts based on severity.</p>
      </div>
    </div>

     <div class="section">
      <h2>${windows_device_event_volume.title}</h2>
      <p>${windows_device_event_volume.description}</p>
      <div id="${windows_device_event_volume}"></div>
      <p>Identifies  windows devices contributing most to security events.</p>

    </div>

      <div class="section">
      <h2>${fortigate_device_event_volume.title}</h2>
      <p>${fortigate_device_event_volume.description}</p>
      <div id="${fortigate_device_event_volume}"></div>
      <p>Identifies  fortigate devices contributing most to security events.</p>

    </div>



  </div>
  </body>
</html> """










































def schedule():
	return "@daily"

def fragments():
	return ["hindustantimes/hindustantimes/fragments/top_entities_involved_in_security_events/","hindustantimes/hindustantimes/fragments/detection_severity_breakdown/","hindustantimes/hindustantimes/fragments/coverage_by_threat_category/","hindustantimes/hindustantimes/fragments/detection_volume_trends_by_time/","hindustantimes/hindustantimes/fragments/top_recurring_threat_detections/","hindustantimes/hindustantimes/fragments/devices_receiving_events_by_source/","hindustantimes/hindustantimes/fragments/windows_device_event_volume/","hindustantimes/hindustantimes/fragments/event_volume_trends_by_time/"]