import streamlit as st
import requests
import pandas as pd
import os
import plotly.express as px
import plotly.graph_objects as go
import math
import datetime
from datetime import timedelta
import logging
from typing import Optional, Dict, List, Any
import json

from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configuration with validation
MAIN_URL = os.getenv("MAIN_URL")
MAIL_URL = os.getenv("MAIL_URL")

# Validate environment variables
if not MAIN_URL or not MAIL_URL:
    st.error("❌ Environment variables MAIN_URL and MAIL_URL must be configured")
    st.stop()

# Page configuration
st.set_page_config(
    page_title="Cybercrime Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': "Cybercrime Detection Dashboard v2.0"
    }
)

# Minimal styling - only essential tweaks
st.markdown("""
<style>
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display: none;}
</style>
""", unsafe_allow_html=True)

# Constants
DEFAULT_ROWS_PER_PAGE = 25
MAX_RETRIES = 3
REQUEST_TIMEOUT = 15

# Initialize session state with proper defaults
def initialize_session_state():
    """Initialize session state variables with proper defaults"""
    defaults = {
        "data": None,
        "selected_row_id": None,
        "current_page": 1,
        "rows_per_page": DEFAULT_ROWS_PER_PAGE,
        "last_refresh": None,
        "view_mode": "overview",
        "scam_filter": "All",
        "threat_filter": [],
        "date_range": None,
        "include_missing_dates": True,
        "loading": False,
        "error_message": None
    }
    
    for key, default_value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

# Data loading with robust error handling
@st.cache_data(ttl=300, show_spinner=False)
def load_data_from_api() -> tuple[List[Dict], Optional[str]]:
    """Load data from API with comprehensive error handling"""
    try:
        logger.info(f"Attempting to fetch data from {MAIN_URL}")
        response = requests.get(MAIN_URL, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            try:
                data = response.json()
                if isinstance(data, dict) and "data" in data:
                    records = data["data"]
                    if isinstance(records, list):
                        logger.info(f"Successfully loaded {len(records)} records")
                        return records, None
                    else:
                        return [], "Invalid data format: 'data' field is not a list"
                else:
                    return [], "Invalid response format: missing 'data' field"
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {e}")
                return [], f"Invalid JSON response: {str(e)}"
        else:
            logger.error(f"HTTP error: {response.status_code}")
            return [], f"Server error: HTTP {response.status_code}"
            
    except requests.exceptions.Timeout:
        logger.error("Request timeout")
        return [], "Request timeout - server may be overloaded"
    except requests.exceptions.ConnectionError:
        logger.error("Connection error")
        return [], "Connection failed - check network connectivity"
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception: {e}")
        return [], f"Network error: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return [], f"Unexpected error: {str(e)}"

def safe_report_to_police(ad_id: str) -> tuple[bool, str]:
    """Send report to police with comprehensive error handling"""
    if not ad_id:
        return False, "Invalid Case ID"
    
    try:
        payload = {"id": str(ad_id)}
        logger.info(f"Reporting case {ad_id} to law enforcement")
        
        response = requests.post(
            MAIL_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            # Update reported status in session state
            if st.session_state.data:
                for i, item in enumerate(st.session_state.data):
                    if str(item.get("id", "")) == str(ad_id):
                        st.session_state.data[i]["reported"] = 1
                        break
            
            logger.info(f"Successfully reported case {ad_id}")
            return True, f"Case {ad_id} successfully reported to Law Enforcement"
        else:
            logger.error(f"Report failed with status {response.status_code}")
            return False, f"Server error: HTTP {response.status_code}"
            
    except requests.exceptions.Timeout:
        logger.error(f"Timeout reporting case {ad_id}")
        return False, "Report timeout - please try again"
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error reporting case {ad_id}")
        return False, "Connection failed - check network connectivity"
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception reporting case {ad_id}: {e}")
        return False, f"Network error: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error reporting case {ad_id}: {e}")
        return False, f"Unexpected error: {str(e)}"

def safe_get_value(data: Dict, key: str, default: Any = None) -> Any:
    """Safely get value from dictionary with proper type handling"""
    try:
        value = data.get(key, default)
        if pd.isna(value) or value == "" or value is None:
            return default
        return value
    except Exception:
        return default

def format_number(value: Any) -> str:
    """Format numbers safely"""
    try:
        if pd.isna(value) or value is None:
            return "0"
        num = float(value)
        if num >= 1000000:
            return f"{num/1000000:.1f}M"
        elif num >= 1000:
            return f"{num/1000:.1f}K"
        else:
            return f"{int(num):,}"
    except (ValueError, TypeError):
        return "0"

def safe_date_parse(date_str: Any) -> Optional[datetime.datetime]:
    """Safely parse date strings"""
    if pd.isna(date_str) or date_str is None or date_str == "":
        return None
    
    try:
        return pd.to_datetime(date_str, errors='coerce', utc=True)
    except Exception:
        return None

# Data processing functions
def preprocess_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Preprocess dataframe with robust error handling"""
    try:
        df_processed = df.copy()
        
        # Handle date columns
        if "date_scraped" in df_processed.columns:
            df_processed["date_scraped"] = df_processed["date_scraped"].apply(safe_date_parse)
        
        # Handle ID column
        if "id" in df_processed.columns:
            df_processed["id"] = df_processed["id"].astype(str)
        
        # Handle numeric columns
        numeric_columns = ["page_like_count", "report_count", "reported"]
        for col in numeric_columns:
            if col in df_processed.columns:
                df_processed[col] = pd.to_numeric(df_processed[col], errors='coerce').fillna(0).astype(int)
        
        # Handle boolean columns
        if "is_scam" in df_processed.columns:
            df_processed["is_scam"] = df_processed["is_scam"].fillna(False).astype(bool)
        
        if "is_active" in df_processed.columns:
            df_processed["is_active"] = df_processed["is_active"].fillna(False).astype(bool)
        
        return df_processed
        
    except Exception as e:
        logger.error(f"Error preprocessing dataframe: {e}")
        return df

def apply_filters(df: pd.DataFrame) -> pd.DataFrame:
    """Apply filters to dataframe with error handling"""
    try:
        filtered_df = df.copy()
        
        # Apply scam filter
        scam_filter = st.session_state.get("scam_filter", "All")
        if scam_filter == "Scam Only" and "is_scam" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["is_scam"] == True]
        elif scam_filter == "Legit Only" and "is_scam" in filtered_df.columns:
            filtered_df = filtered_df[filtered_df["is_scam"] == False]
        
        # Apply threat level filter
        threat_filter = st.session_state.get("threat_filter", [])
        if threat_filter and "threat_level" in filtered_df.columns:
            tl_upper = filtered_df["threat_level"].astype(str).str.upper().str.strip()
            other_mask = (~tl_upper.isin(["HIGH", "MEDIUM", "LOW"])) | filtered_df["threat_level"].isna() | (tl_upper == "")
            threat_category = tl_upper.where(~other_mask, "OTHER")
            filtered_df = filtered_df[threat_category.isin(threat_filter)]
        
        # Apply date range filter
        if "date_range" in st.session_state and "date_scraped" in filtered_df.columns:
            date_range = st.session_state.get("date_range")
            if date_range:
                try:
                    if isinstance(date_range, (list, tuple)) and len(date_range) == 2:
                        start_date, end_date = date_range
                        if start_date and end_date:
                            if end_date < start_date:
                                start_date, end_date = end_date, start_date
                            
                            include_missing = st.session_state.get("include_missing_dates", True)
                            ds = pd.to_datetime(filtered_df["date_scraped"], errors="coerce", utc=True)
                            
                            start_ts = pd.Timestamp(datetime.datetime.combine(start_date, datetime.time.min))
                            end_ts = pd.Timestamp(datetime.datetime.combine(end_date, datetime.time.max))
                            
                            # Handle timezone
                            if ds.dt.tz is not None:
                                start_ts = start_ts.tz_localize(ds.dt.tz.zone)
                                end_ts = end_ts.tz_localize(ds.dt.tz.zone)
                            
                            date_mask = (ds >= start_ts) & (ds <= end_ts)
                            if include_missing:
                                date_mask = date_mask | ds.isna()
                            
                            filtered_df = filtered_df[date_mask]
                except Exception as e:
                    logger.error(f"Error applying date filter: {e}")
        
        return filtered_df
        
    except Exception as e:
        logger.error(f"Error applying filters: {e}")
        return df

# UI Components
def render_header():
    """Render application header using native Streamlit components"""
    st.title("🛡️ Cybercrime Detection Dashboard")
    st.subheader("Advanced Threat Intelligence & Law Enforcement Platform")

def render_system_status():
    """Render system status using native Streamlit components"""
    st.subheader("📡 System Status")
    
    # Test API connectivity
    try:
        response = requests.get(MAIN_URL, timeout=5)
        if response.status_code == 200:
            st.success("🟢 API Connected")
        else:
            st.error(f"🔴 API Error (HTTP {response.status_code})")
    except requests.exceptions.Timeout:
        st.warning("🟡 API Timeout")
    except requests.exceptions.ConnectionError:
        st.error("🔴 Connection Failed")
    except Exception as e:
        st.error(f"🔴 System Error: {str(e)}")
    
    # Data freshness indicator
    if st.session_state.last_refresh:
        time_diff = datetime.datetime.now() - st.session_state.last_refresh
        minutes_ago = time_diff.total_seconds() / 60
        
        if minutes_ago < 5:
            st.success(f"✅ Data Fresh ({int(minutes_ago)}m ago)")
        elif minutes_ago < 30:
            st.warning(f"⚠️ Data Aging ({int(minutes_ago)}m ago)")
        else:
            st.error(f"🔴 Data Stale ({int(minutes_ago)}m ago)")
    else:
        st.info("📊 No data loaded")

def render_data_controls():
    """Render data management controls"""
    st.subheader("🔄 Data Management")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔄 Refresh Data", type="primary", use_container_width=True):
            with st.spinner("Fetching latest intelligence..."):
                st.session_state.loading = True
                load_data_from_api.clear()  # Clear cache
                data, error = load_data_from_api()
                
                if error:
                    st.session_state.error_message = error
                    st.error(f"❌ {error}")
                else:
                    st.session_state.data = data
                    st.session_state.last_refresh = datetime.datetime.now()
                    st.session_state.current_page = 1
                    st.session_state.error_message = None
                    st.success(f"✅ Loaded {len(data)} records")
                    st.balloons()
                
                st.session_state.loading = False
                st.rerun()
    
    with col2:
        if st.button("📊 Export Data", use_container_width=True):
            if st.session_state.data:
                try:
                    df_export = pd.DataFrame(st.session_state.data)
                    csv_data = df_export.to_csv(index=False)
                    
                    st.download_button(
                        label="💾 Download CSV",
                        data=csv_data,
                        file_name=f"cybercrime_intel_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                except Exception as e:
                    st.error(f"Export failed: {str(e)}")
            else:
                st.info("No data to export")

def render_view_selector():
    """Render view mode selector"""
    st.subheader("👀 Dashboard Views")
    
    view_options = {
        "📋 Tactical Overview": "overview",
        "📊 Analytics Center": "analytics", 
        "🔍 Case Investigation": "detailed"
    }
    
    selected_view = st.radio(
        "Select view mode:",
        list(view_options.keys()),
        index=list(view_options.values()).index(st.session_state.view_mode)
    )
    
    st.session_state.view_mode = view_options[selected_view]

def render_filters():
    """Render intelligent filter controls"""
    with st.expander("🎯 Intelligence Filters", expanded=True):
        if not st.session_state.data:
            st.info("Load data to access filters")
            return
        
        df = pd.DataFrame(st.session_state.data)
        
        # Quick action buttons
        st.write("**🚀 Quick Filters:**")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🚨 High Threats", use_container_width=True):
                st.session_state.scam_filter = "Scam Only"
                st.session_state.threat_filter = ["HIGH"]
                st.rerun()
        
        with col2:
            if st.button("✅ Safe Content", use_container_width=True):
                st.session_state.scam_filter = "Legit Only"
                st.rerun()
        
        with col3:
            if st.button("🗑️ Clear All", use_container_width=True):
                st.session_state.scam_filter = "All"
                st.session_state.threat_filter = []
                st.session_state.date_range = None
                st.rerun()
        
        st.divider()
        
        # Classification filter
        scam_options = ["All Records", "🚨 Threats Only", "✅ Safe Only"]
        scam_filter_display = st.selectbox("🎯 Content Classification:", scam_options)
        
        if "Threats Only" in scam_filter_display:
            st.session_state.scam_filter = "Scam Only"
        elif "Safe Only" in scam_filter_display:
            st.session_state.scam_filter = "Legit Only"
        else:
            st.session_state.scam_filter = "All"
        
        # Threat level filter
        if "threat_level" in df.columns:
            threat_levels = ["HIGH", "MEDIUM", "LOW"]
            existing_levels = df["threat_level"].astype(str).str.upper().unique()
            available_levels = [level for level in threat_levels if level in existing_levels]
            
            if len(df[~df["threat_level"].astype(str).str.upper().isin(threat_levels)]) > 0:
                available_levels.append("OTHER")
            
            st.session_state.threat_filter = st.multiselect(
                "⚠️ Threat Priority Levels:",
                available_levels,
                default=st.session_state.get("threat_filter", available_levels)
            )
        
        # Date range filter
        if "date_scraped" in df.columns:
            df_dates = df.dropna(subset=["date_scraped"])
            if not df_dates.empty:
                date_col = pd.to_datetime(df_dates["date_scraped"], errors="coerce")
                valid_dates = date_col.dropna()
                
                if not valid_dates.empty:
                    min_date = valid_dates.min().date()
                    max_date = valid_dates.max().date()
                    
                    st.write("**📅 Date Range Filter:**")
                    
                    # Quick date buttons
                    date_col1, date_col2, date_col3 = st.columns(3)
                    today = datetime.date.today()
                    
                    with date_col1:
                        if st.button("Today", use_container_width=True):
                            st.session_state.date_range = (today, today)
                            st.rerun()
                    
                    with date_col2:
                        if st.button("Last Week", use_container_width=True):
                            week_ago = today - timedelta(days=7)
                            st.session_state.date_range = (week_ago, today)
                            st.rerun()
                    
                    with date_col3:
                        if st.button("Last Month", use_container_width=True):
                            month_ago = today - timedelta(days=30)
                            st.session_state.date_range = (month_ago, today)
                            st.rerun()
                    
                    # Custom date range
                    current_range = st.session_state.get("date_range", (min_date, max_date))
                    st.session_state.date_range = st.date_input(
                        "Custom date range:",
                        value=current_range,
                        min_value=min_date,
                        max_value=max_date
                    )
                    
                    st.session_state.include_missing_dates = st.checkbox(
                        "Include records with missing dates",
                        value=st.session_state.get("include_missing_dates", True)
                    )

def render_metrics(df: pd.DataFrame):
    """Render key performance metrics using Streamlit metrics"""
    st.subheader("📊 Intelligence Overview")
    
    try:
        total_records = len(df)
        
        if total_records == 0:
            st.warning("No records match current filters")
            return
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("📋 Total Cases", format_number(total_records))
        
        with col2:
            if "is_scam" in df.columns:
                threat_count = len(df[df["is_scam"] == True])
                threat_rate = (threat_count / total_records * 100) if total_records > 0 else 0
                st.metric("🚨 Active Threats", format_number(threat_count), f"{threat_rate:.1f}%")
            else:
                st.metric("🚨 Active Threats", "N/A")
        
        with col3:
            if "is_scam" in df.columns:
                safe_count = len(df[df["is_scam"] == False])
                st.metric("✅ Verified Safe", format_number(safe_count))
            else:
                st.metric("✅ Verified Safe", "N/A")
        
        with col4:
            if "threat_level" in df.columns:
                high_threats = len(df[df["threat_level"].astype(str).str.upper() == "HIGH"])
                st.metric("🔥 Critical Cases", format_number(high_threats))
            else:
                st.metric("🔥 Critical Cases", "N/A")
        
        with col5:
            if "reported" in df.columns:
                reported_count = len(df[df["reported"] == 1])
                reported_rate = (reported_count / total_records * 100) if total_records > 0 else 0
                st.metric("📧 Reported", format_number(reported_count), f"{reported_rate:.1f}%")
            else:
                st.metric("📧 Reported", "N/A")
                
    except Exception as e:
        logger.error(f"Error rendering metrics: {e}")
        st.error(f"Error calculating metrics: {str(e)}")

def render_overview_charts(df: pd.DataFrame):
    """Render overview charts using Plotly"""
    if len(df) == 0:
        return
    
    try:
        st.subheader("📈 Threat Intelligence Overview")
        
        chart_col1, chart_col2, chart_col3 = st.columns(3)
        
        with chart_col1:
            if "is_scam" in df.columns:
                threat_counts = df["is_scam"].value_counts()
                if not threat_counts.empty:
                    fig_threats = px.pie(
                        values=threat_counts.values,
                        names=["✅ Safe" if not x else "🚨 Threat" for x in threat_counts.index],
                        title="Threat Classification"
                    )
                    fig_threats.update_traces(textposition="inside", textinfo="percent+label")
                    fig_threats.update_layout(height=300)
                    st.plotly_chart(fig_threats, use_container_width=True)
        
        with chart_col2:
            if "threat_level" in df.columns:
                threat_levels = df["threat_level"].fillna("UNKNOWN").astype(str).str.upper()
                threat_levels = threat_levels.where(threat_levels.isin(["HIGH", "MEDIUM", "LOW"]), "OTHER")
                level_counts = threat_levels.value_counts()
                
                if not level_counts.empty:
                    fig_levels = px.bar(
                        x=level_counts.index,
                        y=level_counts.values,
                        title="Threat Severity"
                    )
                    fig_levels.update_layout(height=300, showlegend=False)
                    st.plotly_chart(fig_levels, use_container_width=True)
        
        with chart_col3:
            if "reported" in df.columns:
                reported_status = df["reported"].map({1: "📧 Reported", 0: "⏳ Pending"})
                status_counts = reported_status.value_counts()
                
                if not status_counts.empty:
                    fig_status = px.pie(
                        values=status_counts.values,
                        names=status_counts.index,
                        title="Enforcement Status"
                    )
                    fig_status.update_traces(textposition="inside", textinfo="percent+label")
                    fig_status.update_layout(height=300)
                    st.plotly_chart(fig_status, use_container_width=True)
                    
    except Exception as e:
        logger.error(f"Error rendering charts: {e}")
        st.error(f"Error generating charts: {str(e)}")

def render_data_table(df: pd.DataFrame):
    """Render main data table with robust pagination"""
    if len(df) == 0:
        st.warning("No records found matching current filters")
        return
    
    try:
        st.subheader("🗃️ Intelligence Database")
        
        # Column selection and formatting
        essential_columns = ["id", "page_name", "is_scam", "scam_type", "threat_level", 
                           "page_like_count", "report_count", "reported", "date_scraped"]
        
        available_columns = [col for col in essential_columns if col in df.columns]
        
        if not available_columns:
            st.error("No essential columns found in data")
            return
        
        display_df = df[available_columns].copy()
        
        # Format columns safely
        if "threat_level" in display_df.columns:
            threat_formatted = display_df["threat_level"].astype(str).str.upper()
            display_df["threat_level"] = threat_formatted.where(
                threat_formatted.isin(["HIGH", "MEDIUM", "LOW"]), "OTHER"
            )
        
        if "is_scam" in display_df.columns:
            display_df["Classification"] = display_df["is_scam"].apply(
                lambda x: "🚨 THREAT" if x else "✅ SAFE"
            )
            display_df = display_df.drop("is_scam", axis=1)
        
        if "reported" in display_df.columns:
            display_df["Status"] = display_df["reported"].apply(
                lambda x: "📧 Reported" if x == 1 else "⏳ Pending"
            )
            display_df = display_df.drop("reported", axis=1)
        
        # Sorting controls
        sort_col1, sort_col2, sort_col3 = st.columns([2, 1, 1])
        
        with sort_col1:
            sort_column = st.selectbox(
                "🔢 Sort by:", 
                list(display_df.columns),
                key="sort_column"
            )
        
        with sort_col2:
            sort_direction = st.selectbox(
                "📊 Order:", 
                ["Ascending", "Descending"],
                key="sort_direction"
            )
        
        with sort_col3:
            st.session_state.rows_per_page = st.selectbox(
                "📄 Rows:", 
                [10, 25, 50, 100], 
                index=1
            )
        
        # Apply sorting
        try:
            ascending = (sort_direction == "Ascending")
            
            if sort_column in ["Classification", "Status"]:
                # Handle categorical sorting
                if sort_column == "Classification":
                    sort_map = {"🚨 THREAT": 0, "✅ SAFE": 1}
                else:  # Status
                    sort_map = {"📧 Reported": 0, "⏳ Pending": 1}
                sort_key = display_df[sort_column].map(sort_map).fillna(999)
            elif sort_column == "threat_level":
                level_map = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "OTHER": 3}
                sort_key = display_df[sort_column].map(level_map).fillna(999)
            elif "date" in sort_column.lower():
                sort_key = pd.to_datetime(display_df[sort_column], errors="coerce")
            else:
                # Try numeric first, then string
                numeric_vals = pd.to_numeric(display_df[sort_column], errors="coerce")
                if numeric_vals.notna().sum() / len(display_df) > 0.5:  # Mostly numeric
                    sort_key = numeric_vals.fillna(-999 if ascending else 999999)
                else:
                    sort_key = display_df[sort_column].astype(str)
            
            display_df = display_df.iloc[sort_key.argsort()[::-1 if not ascending else 1]]
            
        except Exception as e:
            logger.error(f"Sorting error: {e}")
            st.warning("Sorting failed, showing unsorted data")
        
        # Pagination
        total_rows = len(display_df)
        total_pages = math.ceil(total_rows / st.session_state.rows_per_page)
        
        if st.session_state.current_page > total_pages:
            st.session_state.current_page = max(1, total_pages)
        
        start_idx = (st.session_state.current_page - 1) * st.session_state.rows_per_page
        end_idx = start_idx + st.session_state.rows_per_page
        paginated_df = display_df.iloc[start_idx:end_idx]
        
        # Display table
        event = st.dataframe(
            paginated_df,
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            column_config={
                "id": st.column_config.TextColumn("🆔 Case ID", width="small"),
                "page_name": st.column_config.TextColumn("📄 Subject", width="medium"), 
                "Classification": st.column_config.TextColumn("🎯 Type", width="small"),
                "scam_type": st.column_config.TextColumn("🏷️ Category", width="medium"),
                "threat_level": st.column_config.TextColumn("⚠️ Priority", width="small"),
                "page_like_count": st.column_config.NumberColumn("👥 Reach", width="small"),
                "report_count": st.column_config.NumberColumn("📊 Reports", width="small"),
                "Status": st.column_config.TextColumn("📮 Status", width="small"),
                "date_scraped": st.column_config.DatetimeColumn("📅 Date", width="medium")
            }
        )
        
        # Pagination controls
        if total_pages > 1:
            nav_col1, nav_col2, nav_col3, nav_col4, nav_col5 = st.columns([1, 1, 2, 1, 1])
            
            with nav_col1:
                if st.button("⏮️ First", disabled=st.session_state.current_page == 1):
                    st.session_state.current_page = 1
                    st.rerun()
            
            with nav_col2:
                if st.button("◀️ Prev", disabled=st.session_state.current_page == 1):
                    st.session_state.current_page -= 1
                    st.rerun()
            
            with nav_col3:
                st.info(f"Page {st.session_state.current_page} of {total_pages} ({total_rows:,} records)")
            
            with nav_col4:
                if st.button("Next ▶️", disabled=st.session_state.current_page == total_pages):
                    st.session_state.current_page += 1
                    st.rerun()
            
            with nav_col5:
                if st.button("Last ⏭️", disabled=st.session_state.current_page == total_pages):
                    st.session_state.current_page = total_pages
                    st.rerun()
        
        # Handle row selection
        if event.selection.rows:
            try:
                selected_idx = event.selection.rows[0]
                actual_idx = start_idx + selected_idx
                selected_case = df.iloc[actual_idx].to_dict()
                st.session_state.selected_row_id = safe_get_value(selected_case, "id", "")
                
                # Quick actions for selected case
                render_quick_actions(selected_case)
                
            except Exception as e:
                logger.error(f"Error handling selection: {e}")
                st.error("Error processing selection")
                
    except Exception as e:
        logger.error(f"Error rendering data table: {e}")
        st.error(f"Error displaying data table: {str(e)}")

def render_quick_actions(case_data: Dict):
    """Render quick actions for selected case"""
    st.divider()
    st.subheader("⚡ Case Actions")
    
    action_col1, action_col2, action_col3, action_col4 = st.columns(4)
    
    with action_col1:
        if st.button("🔍 Investigate", type="primary", use_container_width=True):
            st.session_state.view_mode = "detailed"
            st.rerun()
    
    with action_col2:
        case_id = safe_get_value(case_data, "id", "")
        is_reported = safe_get_value(case_data, "reported", 0) == 1
        
        if not is_reported and case_id:
            if st.button("📧 Report", type="secondary", use_container_width=True):
                success, message = safe_report_to_police(case_id)
                if success:
                    st.success(message)
                    st.balloons()
                else:
                    st.error(message)
                st.rerun()
        else:
            st.success("✅ Reported" if is_reported else "❌ No ID")
    
    with action_col3:
        is_threat = safe_get_value(case_data, "is_scam", False)
        if is_threat:
            st.error("🚨 THREAT")
        else:
            st.success("✅ SAFE")
    
    with action_col4:
        threat_level = safe_get_value(case_data, "threat_level", "UNKNOWN").upper()
        if threat_level == "HIGH":
            st.error("🔥 CRITICAL")
        elif threat_level == "MEDIUM":
            st.warning("⚠️ ELEVATED")
        elif threat_level == "LOW":
            st.success("✅ LOW")
        else:
            st.info("❓ UNKNOWN")

def render_detailed_view(case_data: Dict):
    """Render detailed case investigation view"""
    st.header("🔍 Case Investigation Report")
    
    case_id = safe_get_value(case_data, "id", "UNKNOWN")
    
    # Case header
    header_col1, header_col2, header_col3 = st.columns([2, 1, 1])
    
    with header_col1:
        st.metric("🆔 Case ID", case_id)
    
    with header_col2:
        if st.button("📋 Back to Overview", key="back_btn"):
            st.session_state.view_mode = "overview"
            st.rerun()
    
    with header_col3:
        is_reported = safe_get_value(case_data, "reported", 0) == 1
        if not is_reported:
            if st.button("📧 File Report", type="primary", key="report_detailed"):
                success, message = safe_report_to_police(case_id)
                if success:
                    st.success(message)
                    st.balloons()
                else:
                    st.error(message)
                st.rerun()
        else:
            st.success("✅ Case Filed")
    
    # Case details in tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "📝 Evidence", "🧠 Analysis", "⚖️ Actions"])
    
    with tab1:
        # Basic metrics
        metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
        
        with metric_col1:
            page_likes = safe_get_value(case_data, "page_like_count", 0)
            st.metric("👥 Page Followers", format_number(page_likes))
        
        with metric_col2:
            reports = safe_get_value(case_data, "report_count", 0)
            st.metric("📊 Citizen Reports", reports)
        
        with metric_col3:
            scam_type = safe_get_value(case_data, "scam_type", "Unknown")
            st.metric("🏷️ Classification", scam_type)
        
        with metric_col4:
            is_active = safe_get_value(case_data, "is_active", False)
            status = "Active" if is_active else "Inactive"
            st.metric("📡 Status", status)
        
        # Case information
        st.subheader("📋 Case Information")
        
        info_col1, info_col2 = st.columns(2)
        
        with info_col1:
            st.write(f"**📄 Page Name:** {safe_get_value(case_data, 'page_name', 'Unknown')}")
            st.write(f"**📅 Date Scraped:** {safe_get_value(case_data, 'date_scraped', 'Unknown')}")
            
            threat_level = safe_get_value(case_data, "threat_level", "UNKNOWN").upper()
            if threat_level == "HIGH":
                st.error("🔥 HIGH THREAT - Immediate action required")
            elif threat_level == "MEDIUM":
                st.warning("⚠️ MEDIUM THREAT - Monitor closely")
            elif threat_level == "LOW":
                st.success("✅ LOW THREAT - Standard processing")
            else:
                st.info("❓ THREAT LEVEL UNKNOWN")
        
        with info_col2:
            profile_pic_url = safe_get_value(case_data, "page_profile_picture_url", "")
            if profile_pic_url:
                try:
                    st.image(profile_pic_url, width=150, caption="Profile Picture")
                except Exception:
                    st.info("Profile picture unavailable")
            else:
                st.info("No profile picture available")
    
    with tab2:
        st.subheader("📝 Digital Evidence")
        
        # Ad content
        ad_text = safe_get_value(case_data, "ad_text", "")
        if ad_text:
            st.text_area("Advertisement Content:", value=ad_text, height=150, disabled=True)
        else:
            st.info("No advertisement text available")
        
        # URLs found
        links_found = safe_get_value(case_data, "links_found", [])
        if links_found:
            if not isinstance(links_found, list):
                links_found = [links_found]
            
            st.subheader("🔗 Suspicious URLs")
            st.warning("⚠️ Do not click these links - they may be malicious")
            for i, link in enumerate(links_found, 1):
                st.code(f"{i}. {link}")
        
        # Technical URLs
        profile_uri = safe_get_value(case_data, "page_profile_uri", "")
        ad_url = safe_get_value(case_data, "ad_url", "")
        
        if profile_uri or ad_url:
            st.subheader("🌐 Source URLs")
            if profile_uri:
                st.code(f"Profile: {profile_uri}")
            if ad_url:
                st.code(f"Ad URL: {ad_url}")
    
    with tab3:
        st.subheader("🧠 AI Analysis")
        
        # Explanation
        explanation = safe_get_value(case_data, "explanation", "")
        if explanation:
            st.info(explanation)
        else:
            st.warning("No AI analysis available")
        
        # Summary points
        summary = safe_get_value(case_data, "summary", [])
        if summary:
            if not isinstance(summary, list):
                summary = [summary]
            
            st.subheader("📋 Key Findings")
            for i, point in enumerate(summary, 1):
                st.write(f"**{i}.** {point}")
        
        # Analysis details in columns
        analysis_col1, analysis_col2 = st.columns(2)
        
        with analysis_col1:
            scam_patterns = safe_get_value(case_data, "scam_patterns", [])
            if scam_patterns:
                if not isinstance(scam_patterns, list):
                    scam_patterns = [scam_patterns]
                
                st.subheader("🔍 Fraud Patterns")
                for pattern in scam_patterns:
                    st.write(f"• {pattern}")
        
        with analysis_col2:
            red_flags = safe_get_value(case_data, "red_flags", [])
            if red_flags:
                if not isinstance(red_flags, list):
                    red_flags = [red_flags]
                
                st.subheader("🚩 Red Flags")
                for flag in red_flags:
                    st.write(f"🚩 {flag}")
    
    with tab4:
        st.subheader("⚖️ Law Enforcement Actions")
        
        recommendations = safe_get_value(case_data, "recommendations", [])
        if recommendations:
            if not isinstance(recommendations, list):
                recommendations = [recommendations]
            
            st.subheader("📋 Recommended Actions")
            for i, rec in enumerate(recommendations, 1):
                st.write(f"**{i}.** {rec}")
        else:
            st.info("No specific recommendations available")
        
        # Priority assessment
        st.divider()
        st.subheader("🎯 Priority Assessment")
        
        priority_score = 0
        factors = []
        
        if safe_get_value(case_data, "is_scam", False):
            priority_score += 40
            factors.append("✅ Confirmed fraud")
        
        threat = safe_get_value(case_data, "threat_level", "").upper()
        if threat == "HIGH":
            priority_score += 30
            factors.append("🔥 High threat level")
        elif threat == "MEDIUM":
            priority_score += 20
            factors.append("⚠️ Medium threat level")
        
        likes = safe_get_value(case_data, "page_like_count", 0)
        if likes > 10000:
            priority_score += 20
            factors.append("📈 High public exposure")
        elif likes > 1000:
            priority_score += 10
            factors.append("📊 Moderate public exposure")
        
        reports = safe_get_value(case_data, "report_count", 0)
        if reports > 5:
            priority_score += 10
            factors.append("📢 Multiple complaints")
        
        # Display priority
        priority_col1, priority_col2 = st.columns(2)
        
        with priority_col1:
            st.metric("Priority Score", f"{priority_score}/100")
        
        with priority_col2:
            if priority_score >= 70:
                st.error("🚨 CRITICAL PRIORITY")
            elif priority_score >= 40:
                st.warning("⚠️ HIGH PRIORITY")  
            elif priority_score >= 20:
                st.info("📋 STANDARD PRIORITY")
            else:
                st.success("📝 LOW PRIORITY")
        
        if factors:
            st.subheader("Priority Factors")
            for factor in factors:
                st.write(f"• {factor}")

def render_analytics_view(df: pd.DataFrame):
    """Render advanced analytics dashboard"""
    st.header("📊 Advanced Threat Analytics")
    
    if len(df) == 0:
        st.warning("No data available for analysis")
        return
    
    try:
        # Time series analysis
        if "date_scraped" in df.columns:
            st.subheader("📈 Threat Timeline")
            
            df_time = df.copy()
            df_time["date_scraped"] = pd.to_datetime(df_time["date_scraped"], errors="coerce")
            df_time = df_time.dropna(subset=["date_scraped"])
            
            if len(df_time) > 0:
                # Daily aggregation
                daily_stats = df_time.groupby([
                    df_time["date_scraped"].dt.date,
                    "is_scam"
                ]).size().reset_index(name="count")
                
                if not daily_stats.empty:
                    fig_timeline = px.line(
                        daily_stats,
                        x="date_scraped",
                        y="count", 
                        color="is_scam",
                        title="Daily Threat Detection Timeline",
                        labels={"date_scraped": "Date", "count": "Cases", "is_scam": "Is Threat"}
                    )
                    fig_timeline.update_layout(height=400)
                    st.plotly_chart(fig_timeline, use_container_width=True)
        
        # Advanced analytics in columns
        analytics_col1, analytics_col2, analytics_col3 = st.columns(3)
        
        with analytics_col1:
            # Top scam types
            if "scam_type" in df.columns and "is_scam" in df.columns:
                threat_df = df[df["is_scam"] == True]
                if len(threat_df) > 0:
                    scam_types = threat_df["scam_type"].value_counts().head(10)
                    if not scam_types.empty:
                        fig_types = px.bar(
                            x=scam_types.values,
                            y=scam_types.index,
                            orientation="h",
                            title="Top Threat Types"
                        )
                        fig_types.update_layout(height=400, showlegend=False)
                        st.plotly_chart(fig_types, use_container_width=True)
        
        with analytics_col2:
            # Report distribution
            if "report_count" in df.columns:
                df["report_bins"] = pd.cut(
                    df["report_count"],
                    bins=[0, 1, 5, 10, float("inf")],
                    labels=["0", "1-5", "6-10", "10+"],
                    include_lowest=True
                )
                report_dist = df["report_bins"].value_counts()
                
                if not report_dist.empty:
                    fig_reports = px.bar(
                        x=report_dist.index,
                        y=report_dist.values,
                        title="Citizen Report Distribution"
                    )
                    fig_reports.update_layout(height=400, showlegend=False)
                    st.plotly_chart(fig_reports, use_container_width=True)
        
        with analytics_col3:
            # Reach vs threat correlation
            if "page_like_count" in df.columns and "is_scam" in df.columns:
                df["reach_category"] = pd.cut(
                    df["page_like_count"],
                    bins=[0, 100, 1000, 10000, float("inf")],
                    labels=["<100", "100-1K", "1K-10K", "10K+"],
                    include_lowest=True
                )
                
                reach_threat = df.groupby(["reach_category", "is_scam"]).size().unstack(fill_value=0)
                
                if not reach_threat.empty:
                    fig_reach = px.bar(
                        reach_threat.reset_index(),
                        x="reach_category",
                        y=[True, False],
                        title="Social Reach vs Threat Status",
                        barmode="stack"
                    )
                    fig_reach.update_layout(height=400)
                    st.plotly_chart(fig_reach, use_container_width=True)
        
        # Summary analytics
        st.subheader("📊 Intelligence Summary")
        
        summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
        
        with summary_col1:
            if "is_scam" in df.columns:
                threat_rate = (len(df[df["is_scam"] == True]) / len(df) * 100) if len(df) > 0 else 0
                st.metric("🎯 Threat Rate", f"{threat_rate:.1f}%")
        
        with summary_col2:
            if "threat_level" in df.columns:
                high_threats = len(df[df["threat_level"].astype(str).str.upper() == "HIGH"])
                st.metric("🔥 Critical Cases", high_threats)
        
        with summary_col3:
            if "reported" in df.columns:
                enforcement_rate = (len(df[df["reported"] == 1]) / len(df) * 100) if len(df) > 0 else 0
                st.metric("📧 Enforcement Rate", f"{enforcement_rate:.1f}%")
        
        with summary_col4:
            if "page_like_count" in df.columns:
                avg_reach = df["page_like_count"].mean()
                st.metric("📈 Avg Reach", format_number(avg_reach))
                
    except Exception as e:
        logger.error(f"Error in analytics view: {e}")
        st.error(f"Analytics error: {str(e)}")

# Main application
def main():
    """Main application entry point"""
    try:
        # Initialize session state
        initialize_session_state()
        
        # Render header
        render_header()
        
        # Main layout
        with st.sidebar:
            render_system_status()
            st.divider()
            render_data_controls()
            st.divider()
            render_view_selector()
            st.divider()
            render_filters()
        
        # Load and process data
        if st.session_state.data is None and not st.session_state.loading:
            with st.spinner("Loading initial data..."):
                data, error = load_data_from_api()
                if error:
                    st.session_state.error_message = error
                    st.error(f"❌ {error}")
                else:
                    st.session_state.data = data
                    st.session_state.last_refresh = datetime.datetime.now()
        
        # Process data if available
        if st.session_state.data:
            try:
                df = pd.DataFrame(st.session_state.data)
                df = preprocess_dataframe(df)
                df_filtered = apply_filters(df)
                
                # Render metrics
                render_metrics(df_filtered)
                
                # Route to appropriate view
                if st.session_state.view_mode == "analytics":
                    render_analytics_view(df_filtered)
                elif st.session_state.view_mode == "detailed":
                    if st.session_state.selected_row_id:
                        # Find selected case
                        selected_case = df[df["id"] == st.session_state.selected_row_id]
                        if not selected_case.empty:
                            render_detailed_view(selected_case.iloc[0].to_dict())
                        else:
                            st.warning("Selected case not found")
                            st.session_state.view_mode = "overview"
                            st.rerun()
                    else:
                        # Auto-select high priority case
                        high_priority = df_filtered[
                            (df_filtered.get("is_scam", False) == True) &
                            (df_filtered.get("threat_level", "").astype(str).str.upper() == "HIGH")
                        ]
                        if not high_priority.empty:
                            render_detailed_view(high_priority.iloc[0].to_dict())
                        else:
                            st.info("No high-priority cases found. Select a case from the overview.")
                            st.session_state.view_mode = "overview"
                            st.rerun()
                else:  # overview mode
                    render_overview_charts(df_filtered)
                    st.divider()
                    render_data_table(df_filtered)
                    
            except Exception as e:
                logger.error(f"Error processing data: {e}")
                st.error(f"Data processing error: {str(e)}")
                
        else:
            # No data available
            st.info("🔌 **System Ready** - Click 'Refresh Data' to load intelligence records")
            
            with st.expander("📋 System Information", expanded=True):
                st.markdown("""
                ### 🛡️ Cybercrime Detection System
                
                This dashboard provides real-time intelligence analysis for cybercrime detection and law enforcement.
                
                **Key Features:**
                - 🤖 AI-powered threat classification
                - 📊 Real-time analytics and reporting  
                - ⚖️ Law enforcement integration
                - 🔍 Advanced case investigation tools
                - 📈 Trend analysis and insights
                
                **System Requirements:**
                - Active internet connection
                - Configured API endpoints
                - Valid authentication credentials
                """)
        
        # Footer
        st.divider()
        st.markdown("""
        <div style="text-align: center; padding: 1rem;">
            <h4>🛡️ Cybercrime Detection Dashboard</h4>
            <p><strong>AI-Powered • Real-time • Secure</strong></p>
            <p><em>Protecting citizens through advanced threat intelligence</em></p>
            <small>© 2024 Cybercrime Intelligence Unit</small>
        </div>
        """, unsafe_allow_html=True)
            
    except Exception as e:
        logger.error(f"Critical application error: {e}")
        st.error("🚨 Critical system error occurred. Please refresh the application.")
        st.exception(e)

if __name__ == "__main__":
    main()