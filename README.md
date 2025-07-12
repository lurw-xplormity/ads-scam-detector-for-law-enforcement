# 🛡️ Ads Scam Detector For Law-Enforcement

A comprehensive web application designed to help law enforcement agencies detect and track potential scam advertisements on social media platforms. The system uses AI-powered analysis to identify scam patterns and provides tools for efficient reporting to authorities.

## 🌟 Features

### 🤖 AI-Powered Scam Detection

- Automated scraping of Facebook ads on a weekly schedule
- Advanced AI analysis to classify ads as legitimate or scams
- Detailed metadata extraction including:
  - Scam patterns identification
  - Threat level assessment (HIGH/MEDIUM/LOW)
  - Red flags detection
  - Actionable recommendations

### 📊 Interactive Dashboard

- **Real-time Analytics**: Visual representations of scam vs legitimate ads distribution
- **Advanced Filtering**: Filter by scam status, threat level, and date range
- **Pagination Support**: Handle large datasets efficiently with customizable rows per page
- **Detailed View**: Click on any ad to see comprehensive analysis including:
  - Page information and profile pictures
  - Full ad text and links
  - AI-generated explanations
  - Identified scam patterns and red flags

### 🚨 Police Reporting System

- One-click reporting to law enforcement
- Track reported vs unreported scams
- Visual indicators for already reported ads
- Automated email notifications to relevant authorities

## 🛠️ Technology Stack

- **Frontend**: Streamlit (Python web framework)
- **Data Visualization**: Plotly for interactive charts
- **HTTP Client**: Requests library
- **Data Processing**: Pandas
- **Environment Management**: python-dotenv
- **Python Version**: 3.12+

## 📋 Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd ads_scam
   ```

2. **Install dependencies using uv**

   ```bash
   pip install uv
   uv sync
   ```

   Or using pip:

   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   Create a [`.env`](.env) file in the root directory:
   ```env
   MAIN_URL=your_api_endpoint_for_ads_data
   MAIL_URL=your_api_endpoint_for_police_reporting
   ```

## 🚀 Usage

1. **Run the application**

   ```bash
   streamlit run app.py
   ```

2. **Access the dashboard**
   Open your browser and navigate to `http://localhost:8501`

3. **Navigate the interface**
   - Use the sidebar to refresh data and apply filters
   - Click on any row in the main table to view detailed information
   - Report suspicious ads directly to police with the "Report to Police" button

## 📊 Data Structure

The application expects data in the following format:

```json
{
    "id": "unique_identifier",
    "page_name": "Page Name",
    "is_scam": true/false,
    "scam_type": "SCAM, SPAM, etc.",
    "threat_level": "HIGH/MEDIUM/LOW",
    "explanation": "AI analysis explanation",
    "summary": ["Key findings"],
    "links_found": ["URLs found in the ad"],
    "scam_patterns": ["Identified patterns"],
    "red_flags": ["Detected red flags"],
    "recommendations": ["Recommended actions"],
    "page_like_count": 1000,
    "report_count": 5,
    "reported": 0/1,
    "date_scraped": "2024-01-01"
}
```

## 🔄 Automated Crawler

The backend crawler automatically:

- Scrapes new Facebook ads weekly
- Analyzes content using AI models
- Updates the database with fresh data
- Maintains historical records for trend analysis

## 🔒 Security & Privacy

- Environment variables for sensitive API endpoints
- No storage of personal user data
- Secure communication with law enforcement APIs
- Compliance with data protection regulations

## 📈 Key Metrics Tracked

- Total number of ads analyzed
- Scam vs legitimate ad ratio
- High-threat ad count
- Number of ads reported to authorities
- Threat level distribution

## 🤝 Contributing

This tool is designed for law enforcement use. For feature requests or bug reports, please contact the development team.

## 📝 License

This project is proprietary software designed for law enforcement agencies. Unauthorized use is prohibited.

## 🆘 Support

For technical support or questions about the system, please contact the technical team through official channels.

---

**Note**: This dashboard is a critical tool in the fight against online scams. Regular monitoring and timely reporting can help protect potential victims and bring scammers to justice.
