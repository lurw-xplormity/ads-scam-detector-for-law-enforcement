import streamlit as st
import requests
import pandas as pd
import os
import plotly.express as px
import plotly.graph_objects as go
import math
import datetime

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

MAIN_URL = os.getenv("MAIN_URL")
MAIL_URL = os.getenv("MAIL_URL")

# Page configuration
st.set_page_config(
    page_title="Scam Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for better styling
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    }
    
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 3rem;
        padding-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
    }
    .scam-badge {
        background-color: #ff4b4b;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 15px;
        font-size: 0.8rem;
        font-weight: bold;
    }
    .legit-badge {
        background-color: #00cc88;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 15px;
        font-size: 0.8rem;
        font-weight: bold;
    }
    .threat-high {
        background-color: #ff4b4b;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 10px;
        font-weight: bold;
    }
    .threat-medium {
        background-color: #ffa500;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 10px;
        font-weight: bold;
    }
    .threat-low {
        background-color: #00cc88;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 10px;
        font-weight: bold;
    }
    .report-button {
        background-color: #dc3545;
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 5px;
        font-weight: bold;
        cursor: pointer;
    }
    .pagination-container {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 1rem;
        margin: 1rem 0;
    }
    .instruction-badge {
        display: inline-block;
        background: linear-gradient(90deg,#1f77b4,#4fa3e3);
        color: #fff;
        padding: 0.45rem 0.85rem;
        border-radius: 25px;
        font-weight: 600;
        letter-spacing: .5px;
        font-size: 0.85rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.15);
        margin-bottom: .75rem;
    }
    .placeholder-panel {
        background: linear-gradient(90deg,#1f77b4,#4fa3e3);
        border: 1px dashed #c3d3e6;
        padding: 1.25rem 1rem;
        border-radius: 10px;
        font-size: 0.9rem;
        line-height: 1.4rem;
    }
    .info-section {
        background-color: rgba(31, 119, 180, 0.08);
        border-left: 4px solid #1f77b4;
        padding: 1rem 1.25rem;
        margin: 1rem 0;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        backdrop-filter: blur(10px);
    }
    .info-section.summary {
        border-left-color: #17a2b8;
        background-color: rgba(23, 162, 184, 0.08);
    }
    .info-section.links {
        border-left-color: #6610f2;
        background-color: rgba(102, 16, 242, 0.08);
    }
    .info-section.patterns {
        border-left-color: #fd7e14;
        background-color: rgba(253, 126, 20, 0.08);
    }
    .info-section.red-flags {
        border-left-color: #dc3545;
        background-color: rgba(220, 53, 69, 0.08);
    }
    .info-section.recommendations {
        border-left-color: #28a745;
        background-color: rgba(40, 167, 69, 0.08);
    }
    .section-title {
        font-size: 1.1rem;
        font-weight: 600;
        margin-bottom: 0.75rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        opacity: 0.95;
    }
    .info-item {
        padding: 0.5rem 0;
        margin-left: 1rem;
        font-size: 0.95rem;
        line-height: 1.6;
        display: flex;
        align-items: flex-start;
        gap: 0.5rem;
        opacity: 0.9;
    }
    .info-item::before {
        content: "•";
        color: #1f77b4;
        font-weight: bold;
        font-size: 1.2rem;
        flex-shrink: 0;
    }
    .info-section.summary .info-item::before {
        color: #17a2b8;
    }
    .info-section.links .info-item::before {
        color: #8b5cf6;
    }
    .info-section.patterns .info-item::before {
        color: #fd7e14;
    }
    .info-section.red-flags .info-item::before {
        color: #ff6b6b;
    }
    .info-section.recommendations .info-item::before {
        color: #51cf66;
    }
    .info-item a {
        color: #4dabf7;
        text-decoration: none;
        word-break: break-all;
    }
    .info-item a:hover {
        text-decoration: underline;
        color: #74c0fc;
    }
    .empty-section {
        font-style: italic;
        padding: 0.5rem 0;
        opacity: 0.7;
    }
</style>
""",
    unsafe_allow_html=True,
)

# Initialize session state
if "data" not in st.session_state:
    st.session_state.data = None
if "selected_row_id" not in st.session_state:
    st.session_state.selected_row_id = None
if "current_page" not in st.session_state:
    st.session_state.current_page = 1
if "rows_per_page" not in st.session_state:
    st.session_state.rows_per_page = 50


# --- Data Loading Helper (moved up so sidebar can use data on first render) ---
def load_initial_data():
    """Load data on app start (idempotent)."""
    if st.session_state.data is None:
        try:
            response = requests.get(MAIN_URL)
            if response.status_code == 200:
                res_data = response.json()
                st.session_state.data = res_data.get("data", [])
            else:
                st.error(f"Failed to load data. Status code: {response.status_code}")
        except Exception as e:
            st.error(f"Error loading data: {str(e)}")
    return st.session_state.data


# Pre-load data BEFORE building sidebar so filters appear immediately
load_initial_data()

# Header
st.markdown(
    '<h1 class="main-header">🛡️ Scam Detection Dashboard</h1>', unsafe_allow_html=True
)

# Add spacing after header
st.markdown("<br>", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.header("🔧 Controls")

    # Add info note about crawler schedule
    st.info(
        "📅 **Note:** The crawler automatically scrapes new data 3 days to keep the database updated with the latest ads."
    )

    # Refresh data button
    if st.button("🔄 Refresh Data", type="primary"):
        with st.spinner("Fetching latest data..."):
            try:
                response = requests.get(MAIN_URL)
                if response.status_code == 200:
                    res_data = response.json()
                    st.session_state.data = res_data.get("data", [])
                    st.session_state.current_page = 1  # Reset to first page
                    st.success("Data refreshed successfully!")
                else:
                    st.error(
                        f"Failed to fetch data. Status code: {response.status_code}"
                    )
            except Exception as e:
                st.error(f"Error fetching data: {str(e)}")

    # Pagination settings
    st.header("📄 Pagination")
    rows_per_page = st.selectbox(
        "Rows per page",
        [5, 10, 20, 50],
        index=3,  # Default to 50 (index=3 corresponds to 50)
        key="rows_per_page_selector",
    )
    st.session_state.rows_per_page = rows_per_page

    # Filters
    st.header("🔍 Filters")

    if st.session_state.data:
        df = pd.DataFrame(st.session_state.data)

        # Scam filter
        scam_filter = st.selectbox(
            "Filter by Scam Status",
            ["All", "Scam Only", "Legit Only"],
            key="_scam_filter_widget",
        )
        st.session_state["scam_filter"] = scam_filter

        # (Temporarily defer threat level filter until after date filtering)
        deferred_threat_needed = "threat_level" in df.columns
        threat_filter = []  # will be built after date capture (no data mutation here)

        # Date range filter (with option to keep rows that have missing/invalid dates)
        if "date_scraped" in df.columns:
            parsed_dates_preview = pd.to_datetime(
                df["date_scraped"],
                errors="coerce",
                infer_datetime_format=True,
                utc=True,
            )
            include_missing_dates = st.checkbox(
                "Include rows with missing/invalid dates",
                value=st.session_state.get("include_missing_dates", True),
                help="If checked, ads without a valid date remain visible regardless of the selected range.",
                key="_include_missing_dates_widget",
            )
            st.session_state["include_missing_dates"] = include_missing_dates
            if parsed_dates_preview.notna().any():
                min_dt = parsed_dates_preview.min().date()
                max_dt = parsed_dates_preview.max().date()
                # Persist previous selection if in bounds; else default full range
                prev_range = st.session_state.get("date_range")
                default_range = (min_dt, max_dt)
                if (
                    prev_range
                    and isinstance(prev_range, tuple)
                    and len(prev_range) == 2
                ):
                    try:
                        if (
                            min_dt <= prev_range[0] <= max_dt
                            and min_dt <= prev_range[1] <= max_dt
                        ):
                            default_range = prev_range
                    except Exception:
                        pass
                date_range = st.date_input(
                    "Date Range",
                    value=default_range,
                    min_value=min_dt,
                    max_value=max_dt,
                    key="_date_range_widget",
                )
                st.session_state["date_range"] = date_range
            else:
                st.warning(
                    "No valid dates found in 'date_scraped' column; date filtering disabled."
                )

    # Threat level filter now (after date filtering so counts reflect visible data)
    if deferred_threat_needed:
        base_levels = ["HIGH", "MEDIUM", "LOW"]
        tl_raw_preview = df["threat_level"]
        tl_upper_preview = tl_raw_preview.astype(str).str.upper().str.strip()
        other_mask_preview = (
            (~tl_upper_preview.isin(base_levels))
            | tl_raw_preview.isna()
            | (tl_upper_preview == "")
        )
        threat_category_preview = tl_upper_preview.where(~other_mask_preview, "OTHER")
        options = [lvl for lvl in base_levels if (threat_category_preview == lvl).any()]
        if (threat_category_preview == "OTHER").any():
            options.append("OTHER")
        prev_tf = st.session_state.get("threat_filter")
        default_opts = prev_tf if prev_tf else options
        threat_filter = st.multiselect(
            "Filter by Threat Level",
            options,
            default=default_opts,
            help="OTHER groups all non HIGH / MEDIUM / LOW values (including blanks, nulls, malformed).",
            key="_threat_filter_widget",
        )
        st.session_state["threat_filter"] = threat_filter
        st.session_state["_other_threat_values"] = (
            sorted(set(tl_raw_preview[other_mask_preview].dropna().astype(str)))
            if other_mask_preview.any()
            else []
        )
        with st.expander("Threat Level Counts (debug)"):
            counts = threat_category_preview.value_counts(dropna=False)
            for cat, val in counts.items():
                st.write(f"{cat}: {val}")
            if st.session_state["_other_threat_values"]:
                st.caption(
                    "OTHER includes raw values: "
                    + ", ".join(st.session_state["_other_threat_values"])
                )

# Main content


def report_to_police(ad_id):
    """Send report to police API"""
    try:
        payload = {"id": ad_id}
        response = requests.post(
            MAIL_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code == 200:
            st.success(f"✅ Successfully reported Ad ID: {ad_id} to police!")

            # Update the reported field in session state
            if st.session_state.data:
                for i, item in enumerate(st.session_state.data):
                    if item.get("id") == ad_id:
                        st.session_state.data[i]["reported"] = 1
                        break

            # Force a rerun to refresh the UI
            st.rerun()
        else:
            st.error(f"❌ Failed to report. Status code: {response.status_code}")
    except Exception as e:
        st.error(f"❌ Error reporting to police: {str(e)}")


def display_list_section(row_data, field_key, title, icon, section_class=""):
    """
    Helper function to display a list section in the detailed view.
    Handles both list and string values gracefully with enhanced styling.

    Args:
        row_data: The data dictionary
        field_key: The key to look up in row_data
        title: The section title to display
        icon: The emoji icon for the section
        section_class: CSS class for styling (summary, links, patterns, red-flags, recommendations)
    """
    import json

    # Normalize to list
    items = row_data.get(field_key)

    if not items:
        return

    # try json parsing if it's a string
    try:
        if isinstance(items, str):
            parsed = json.loads(items)
            if isinstance(parsed, list):
                items = parsed
    except Exception:
        pass

    if not isinstance(items, list):
        items = [items]

    # Filter out empty items
    items = [item for item in items if item]

    if not items:
        return

    # Create the section HTML
    items_html = ""
    for item in items:
        item_str = str(item).strip()
        # Check if item is a URL for links section
        if section_class == "links" and (
            item_str.startswith("http://") or item_str.startswith("https://")
        ):
            items_html += f'<div class="info-item"><a href="{item_str}" target="_blank">{item_str}</a></div>'
        else:
            items_html += f'<div class="info-item">{item_str}</div>'

    section_html = f"""
    <div class="info-section {section_class}">
        <div class="section-title">{icon} {title}</div>
        {items_html}
    </div>
    """

    st.markdown(section_html, unsafe_allow_html=True)


def show_detailed_view(row_data):
    """Show detailed view of selected row"""
    st.header("📋 Detailed View")

    # Add Report to Police button at the top
    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        st.write(f"**Selected ID:** {row_data.get('id', 'N/A')}")

    with col2:
        if row_data.get("is_scam") == 0:
            st.markdown(
                '<span class="legit-badge">✓ LEGIT</span>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<span class="scam-badge">⚠️ SCAM</span>',
                unsafe_allow_html=True,
            )

    with col3:
        if row_data.get("reported") == 1:
            st.markdown(
                '<span class="legit-badge">✓ Already Reported</span>',
                unsafe_allow_html=True,
            )
        # elif row_data.get("is_scam") == 0:
        #     st.markdown(
        #         '<span class="legit-badge">✓ LEGIT</span>',
        #         unsafe_allow_html=True,
        #     )
        else:
            if st.button("🚨 Report to Police", type="primary", key="report_button"):
                report_to_police(row_data.get("id"))



    # Basic Information
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📊 Basic Information")
        st.write(f"**ID:** {row_data.get('id', 'N/A')}")
        st.write(f"**Page Name:** {row_data.get('page_name', 'N/A')}")
        st.write(f"**Page Likes:** {row_data.get('page_like_count', 'N/A')}")
        st.write(f"**Is Active:** {row_data.get('is_active', 'N/A')}")
        st.write(f"**Date Scraped:** {row_data.get('date_scraped', 'N/A')}")

    with col2:
        st.subheader("🚨 Scam Analysis")
        scam_status = "SCAM" if row_data.get("is_scam", False) else "LEGIT"
        st.write(f"**Status:** {scam_status}")
        st.write(f"**Type:** {row_data.get('scam_type', 'N/A')}")
        st.write(f"**Threat Level:** {row_data.get('threat_level', 'N/A')}")
        st.write(f"**Report Count:** {row_data.get('report_count', 'N/A')}")

    # Profile Picture
    if row_data.get("page_profile_picture_url"):
        st.subheader("🖼️ Profile Picture")
        st.image(row_data["page_profile_picture_url"], width=150)

    # Ad Text
    if row_data.get("ad_text"):
        st.subheader("📝 Ad Text")
        st.text_area("Ad Text", value=row_data["ad_text"], height=300, disabled=True)

    # Explanation
    if row_data.get("explanation"):
        st.subheader("💡 Analysis Explanation")
        st.write(row_data["explanation"])

    # Display list sections using reusable helper function with enhanced styling
    st.markdown("---")
    st.subheader("🔍 Detailed Analysis")

    display_list_section(row_data, "summary", "Summary", "📋", "summary")
    display_list_section(row_data, "links_found", "Links Found", "🔗", "links")
    display_list_section(row_data, "scam_patterns", "Scam Patterns", "🔍", "patterns")
    display_list_section(row_data, "red_flags", "Red Flags", "🚩", "red-flags")
    display_list_section(
        row_data, "recommendations", "Recommendations", "💼", "recommendations"
    )

    # URLs
    if row_data.get("page_profile_uri"):
        st.subheader("🌐 URLs")
        st.write(f"**Profile URI:** {row_data['page_profile_uri']}")
    if row_data.get("ad_url"):
        st.write(f"**Ad URL:** {row_data['ad_url']}")


def paginate_dataframe(df, page_size, page_num):
    """Paginate dataframe"""
    start_idx = (page_num - 1) * page_size
    end_idx = start_idx + page_size
    return df.iloc[start_idx:end_idx]


def show_pagination_controls(total_rows, rows_per_page, current_page):
    """Show pagination controls"""
    total_pages = math.ceil(total_rows / rows_per_page)

    if total_pages <= 1:
        return current_page

    st.markdown("---")

    # Pagination controls
    col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])

    with col1:
        if st.button("⏮️ First", disabled=(current_page == 1)):
            st.session_state.current_page = 1
            st.rerun()

    with col2:
        if st.button("◀️ Previous", disabled=(current_page == 1)):
            st.session_state.current_page = current_page - 1
            st.rerun()

    with col3:
        st.write(f"Page {current_page} of {total_pages} ({total_rows} total records)")

    with col4:
        if st.button("Next ▶️", disabled=(current_page == total_pages)):
            st.session_state.current_page = current_page + 1
            st.rerun()

    with col5:
        if st.button("Last ⏭️", disabled=(current_page == total_pages)):
            st.session_state.current_page = total_pages
            st.rerun()

    # Page jump
    st.markdown("---")
    jump_col1, jump_col2, jump_col3 = st.columns([1, 1, 2])

    with jump_col1:
        page_input = st.number_input(
            "Jump to page:",
            min_value=1,
            max_value=total_pages,
            value=current_page,
            key="page_jump",
        )

    with jump_col2:
        if st.button("Go"):
            st.session_state.current_page = page_input
            st.rerun()

    return current_page


# Data already loaded earlier; just reference
data = st.session_state.data

if data:
    df = pd.DataFrame(data)

    # Global date parsing (ensure consistent dtype for sorting/filtering)
    if "date_scraped" in df.columns:
        df["date_scraped"] = pd.to_datetime(
            df["date_scraped"], errors="coerce", utc=True
        )

    # Ensure ID column is string type to avoid Arrow serialization issues
    if "id" in df.columns:
        df["id"] = df["id"].astype(str)

    # Convert numeric columns to proper types, handling errors
    if "page_like_count" in df.columns:
        df["page_like_count"] = (
            pd.to_numeric(df["page_like_count"], errors="coerce").fillna(0).astype(int)
        )

    if "report_count" in df.columns:
        df["report_count"] = (
            pd.to_numeric(df["report_count"], errors="coerce").fillna(0).astype(int)
        )

    if "reported" in df.columns:
        df["reported"] = (
            pd.to_numeric(df["reported"], errors="coerce").fillna(0).astype(int)
        )

    # Apply filters
    scam_filter = st.session_state.get("scam_filter")
    if scam_filter == "Scam Only" and "is_scam" in df.columns:
        df = df[df["is_scam"] == True]
    elif scam_filter == "Legit Only" and "is_scam" in df.columns:
        df = df[df["is_scam"] == False]

    threat_filter = st.session_state.get("threat_filter", [])
    if threat_filter and "threat_level" in df.columns:
        if "_threat_category_series" in st.session_state:
            full_threat_cat = st.session_state["_threat_category_series"]
            # Rebuild on current df index (some rows may have been filtered by scam filter)
            tl_upper = df["threat_level"].astype(str).str.upper().str.strip()
            other_mask = (
                (~tl_upper.isin(["HIGH", "MEDIUM", "LOW"]))
                | df["threat_level"].isna()
                | (tl_upper == "")
            )
            threat_category = tl_upper.where(~other_mask, "OTHER")
        else:
            tl_upper = df["threat_level"].astype(str).str.upper().str.strip()
            other_mask = (
                (~tl_upper.isin(["HIGH", "MEDIUM", "LOW"]))
                | df["threat_level"].isna()
                | (tl_upper == "")
            )
            threat_category = tl_upper.where(~other_mask, "OTHER")
        df = df[threat_category.isin(threat_filter)]

    # Apply date range filter (single application here) using session state.
    # Handle transitional single-date selection gracefully.
    if "date_range" in st.session_state and "date_scraped" in df.columns:
        raw_range = st.session_state["date_range"]
        start_date = end_date = None
        # Normalize raw_range from possible types: date, (date,), (start,end)
        if isinstance(raw_range, (list, tuple)):
            if len(raw_range) == 2 and raw_range[0] and raw_range[1]:
                start_date, end_date = raw_range
            elif len(raw_range) == 1 and raw_range[0]:
                start_date = end_date = raw_range[0]
        else:  # single date object
            start_date = end_date = raw_range

        if start_date is not None and end_date is not None:
            if end_date < start_date:
                start_date, end_date = end_date, start_date
            include_missing_dates = st.session_state.get("include_missing_dates", True)
            ds = pd.to_datetime(df["date_scraped"], errors="coerce", utc=True)
            tzinfo = ds.dt.tz
            start_ts = pd.Timestamp(
                datetime.datetime.combine(start_date, datetime.time.min)
            )
            end_ts = pd.Timestamp(
                datetime.datetime.combine(end_date, datetime.time.max)
            )
            if tzinfo is not None:
                start_ts = start_ts.tz_localize(tzinfo)
                end_ts = end_ts.tz_localize(tzinfo)
            base_mask = (ds >= start_ts) & (ds <= end_ts)
            mask = base_mask | ds.isna() if include_missing_dates else base_mask
            df = df[mask]

    # Dashboard metrics
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        total_ads = len(df)
        st.metric("📊 Total Ads", total_ads)

    with col2:
        scam_count = len(df[df["is_scam"] == True]) if "is_scam" in df.columns else 0
        st.metric("🚨 Scam Ads", scam_count)

    with col3:
        legit_count = len(df[df["is_scam"] == False]) if "is_scam" in df.columns else 0
        st.metric("✅ Legit Ads", legit_count)

    with col4:
        high_threat = (
            len(df[df["threat_level"] == "HIGH"]) if "threat_level" in df.columns else 0
        )
        st.metric("⚠️ High Threat", high_threat)

    with col5:
        reported_count = len(df[df["reported"] == 1]) if "reported" in df.columns else 0
        st.metric("📮 Reported", reported_count)

    # Filter summary badge (situational awareness for investigators)
    active_filters = []
    scam_filter_state = st.session_state.get("scam_filter")
    if scam_filter_state and scam_filter_state != "All":
        active_filters.append(f"Scam: {scam_filter_state}")
    tfilt = st.session_state.get("threat_filter")
    if tfilt:
        active_filters.append("Threat: " + ",".join(tfilt))
    if st.session_state.get("date_range"):
        dr = st.session_state.get("date_range")
        try:
            if isinstance(dr, (list, tuple)) and len(dr) == 2:
                active_filters.append(f"Date: {dr[0]} → {dr[1]}")
        except Exception:
            pass
    if active_filters:
        st.markdown(
            f"<span class='instruction-badge'>Active Filters: {' | '.join(active_filters)}</span>",
            unsafe_allow_html=True,
        )

    # Charts
    if len(df) > 0:
        st.header("📈 Analytics")

        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            # Scam vs Legit pie chart
            if "is_scam" in df.columns:
                scam_counts = df["is_scam"].value_counts()
                fig_pie = px.pie(
                    values=scam_counts.values,
                    names=["Legit" if not x else "Scam" for x in scam_counts.index],
                    title="Scam vs Legit Distribution",
                    color_discrete_map={"Scam": "#ff4b4b", "Legit": "#00cc88"},
                )
                st.plotly_chart(fig_pie, use_container_width=True)

        with chart_col2:
            # Threat level distribution
            if "threat_level" in df.columns:
                # Normalize and bucket threat levels: only HIGH, MEDIUM, LOW retained; others -> OTHER
                normalized = df["threat_level"].fillna("OTHER").astype(str).str.upper()
                normalized = normalized.where(
                    normalized.isin(["HIGH", "MEDIUM", "LOW"]), "OTHER"
                )

                order = ["HIGH", "MEDIUM", "LOW", "OTHER"]
                threat_counts = (
                    normalized.value_counts().reindex(order, fill_value=0).reset_index()
                )
                threat_counts.columns = ["Threat Level", "Count"]

                fig_bar = px.bar(
                    threat_counts,
                    x="Threat Level",
                    y="Count",
                    title="Threat Level Distribution (Other grouped)",
                    color="Threat Level",
                    category_orders={"Threat Level": order},
                    color_discrete_map={
                        "HIGH": "#ff4b4b",
                        "MEDIUM": "#ffa500",
                        "LOW": "#00cc88",
                        "OTHER": "#6c757d",
                    },
                )
                fig_bar.update_layout(
                    yaxis_title="Ads Count", xaxis_title="Threat Level"
                )
                st.plotly_chart(fig_bar, use_container_width=True)

        # Supplementary analytics for deeper investigative context
        with st.expander("🔎 Advanced Analytics", expanded=False):
            # Time series volume
            if "date_scraped" in df.columns and df["date_scraped"].notna().any():
                daily_counts = (
                    df["date_scraped"].dt.date.value_counts().sort_index().reset_index()
                )
                daily_counts.columns = ["Date", "Ads"]
                if not daily_counts.empty:
                    fig_daily = px.line(
                        daily_counts,
                        x="Date",
                        y="Ads",
                        markers=True,
                        title="Daily Ads Ingested",
                    )
                    fig_daily.update_layout(
                        xaxis_title="Date", yaxis_title="Count of Ads"
                    )
                    st.plotly_chart(fig_daily, use_container_width=True)

            # Top pages by scam ad frequency
            if "page_name" in df.columns and "is_scam" in df.columns:
                top_pages = (
                    df[df["is_scam"] == True]["page_name"]
                    .value_counts()
                    .head(10)
                    .reset_index()
                )
                if not top_pages.empty:
                    top_pages.columns = ["Page", "Scam Ads"]
                    fig_top_pages = px.bar(
                        top_pages,
                        x="Scam Ads",
                        y="Page",
                        orientation="h",
                        title="Top 10 Pages by Scam Ad Count",
                        color="Scam Ads",
                        color_continuous_scale="Reds",
                    )
                    fig_top_pages.update_layout(yaxis_categoryorder="total ascending")
                    st.plotly_chart(fig_top_pages, use_container_width=True)

            # Threat level trend (stacked area)
            if (
                "threat_level" in df.columns
                and "date_scraped" in df.columns
                and df["date_scraped"].notna().any()
            ):
                tl_norm = df["threat_level"].fillna("OTHER").astype(str).str.upper()
                tl_norm = tl_norm.where(
                    tl_norm.isin(["HIGH", "MEDIUM", "LOW"]), "OTHER"
                )
                tl_trend = (
                    df.assign(_tl=tl_norm, _date=df["date_scraped"].dt.date)
                    .groupby(["_date", "_tl"])
                    .size()
                    .reset_index(name="count")
                )
                if not tl_trend.empty:
                    fig_area = px.area(
                        tl_trend,
                        x="_date",
                        y="count",
                        color="_tl",
                        title="Threat Level Trend Over Time",
                        category_orders={"_tl": ["HIGH", "MEDIUM", "LOW", "OTHER"]},
                        color_discrete_map={
                            "HIGH": "#ff4b4b",
                            "MEDIUM": "#ffa500",
                            "LOW": "#00cc88",
                            "OTHER": "#6c757d",
                        },
                    )
                    fig_area.update_layout(
                        xaxis_title="Date",
                        yaxis_title="Ads Count",
                        legend_title="Threat Level",
                    )
                    st.plotly_chart(fig_area, use_container_width=True)

            st.caption(
                "These charts support pattern recognition: volume spikes, prolific sources, and escalation trends help prioritization."
            )

    # Main data table with pagination
    st.header("📋 Ads Overview")

    # Instruction badge prompting selection
    st.markdown(
        "<span class='instruction-badge'>Select an ad row to view the detailed intelligence report below ▼</span>",
        unsafe_allow_html=True,
    )

    # Select important columns for the main table
    important_columns = [
        "ad_url",
        "id",
        "page_name",
        "is_scam",
        "scam_type",
        "threat_level",
        "page_like_count",
        "report_count",
        "reported",  # Add reported column
        "date_scraped",
    ]

    # Filter columns that exist in the dataframe
    display_columns = [col for col in important_columns if col in df.columns]

    if display_columns:
        # Create display dataframe
        display_df = df[display_columns].copy()

        # Put the ad_url in a link format (HTML inside a table cell)
        # if "ad_url" in display_df.columns:
        #     display_df["ad_url"] = display_df["ad_url"].apply(
        #         lambda x: f'<a href="{x}" target="_blank">Link</a>' if pd.notna(x) else ""
        #     )

        if "threat_level" in display_df.columns:
            tl_disp = display_df["threat_level"].astype(str).str.upper().str.strip()
            base_levels = {"HIGH", "MEDIUM", "LOW"}
            display_df["threat_level"] = tl_disp.where(
                tl_disp.isin(base_levels), "OTHER"
            )

        # Normalize threat level for display consistency
        if "threat_level" in display_df.columns:
            tl_disp = display_df["threat_level"].astype(str).str.upper().str.strip()
            base_levels = {"HIGH", "MEDIUM", "LOW"}
            display_df["threat_level"] = tl_disp.where(
                tl_disp.isin(base_levels), "OTHER"
            )

        # Format the display
        if "is_scam" in display_df.columns:
            display_df["Status"] = display_df["is_scam"].apply(
                lambda x: "SCAM" if x else "LEGIT"
            )
            display_df = display_df.drop("is_scam", axis=1)

        # Format reported column with tick/cross
        if "reported" in display_df.columns:
            display_df["Reported"] = display_df.apply(
                lambda row: "✅" if row["reported"] == 1 else ("❌" if ("Status" in display_df.columns and row["Status"] != "LEGIT") else "-"),
                axis=1
            )
            display_df = display_df.drop("reported", axis=1)

        # Paginate the data
        current_page = st.session_state.current_page
        rows_per_page = st.session_state.rows_per_page

        # --- Server-side Sorting Controls (applied BEFORE pagination) ---
        with st.container():
            sort_cols_available = [c for c in display_df.columns if c not in []]
            default_sort_col = (
                "date_scraped"
                if "date_scraped" in sort_cols_available
                else sort_cols_available[0]
            )
            sort_col = st.selectbox(
                "Sort by column (server-side)",
                sort_cols_available,
                index=sort_cols_available.index(default_sort_col),
                key="sort_column_select",
            )
            sort_dir = st.radio(
                "Order",
                ["Ascending", "Descending"],
                index=1,
                horizontal=True,
                key="sort_direction_select",
            )

            # (Optional) secondary sort can be added later; for now single column
            ascending = True if sort_dir == "Ascending" else False

            col_series = display_df[sort_col]

            # Build a stable, uniform sort key to avoid mixed-type comparison errors
            if sort_col == "Status":
                order_map = {"SCAM": 0, "LEGIT": 1}
                sort_key = col_series.map(order_map).fillna(99)
            elif sort_col == "Reported":
                order_map = {"✅": 0, "❌": 1}
                sort_key = col_series.map(order_map).fillna(99)
            elif sort_col.lower().startswith("date"):
                sort_key = pd.to_datetime(col_series, errors="coerce")
            else:
                # Try numeric; if largely numeric use it; else fallback to string
                numeric_try = pd.to_numeric(col_series, errors="coerce")
                numeric_ratio = numeric_try.notna().mean()
                if numeric_ratio >= 0.8:  # majority numeric
                    # Fill NaNs with extreme sentinel so they sort last/first
                    fill_value = (
                        numeric_try.max() + 1 if ascending else numeric_try.min() - 1
                    )
                    sort_key = numeric_try.fillna(fill_value)
                else:
                    sort_key = col_series.astype(str)

            display_df = (
                display_df.assign(_sort_key=sort_key)
                .sort_values("_sort_key", ascending=ascending, kind="mergesort")
                .drop(columns=["_sort_key"])
            )
            # mergesort is stable so future multi-column sorts can layer

        # Reset page if it's out of bounds
        total_pages = math.ceil(len(display_df) / rows_per_page)
        if current_page > total_pages and total_pages > 0:
            st.session_state.current_page = 1
            current_page = 1

        paginated_df = paginate_dataframe(display_df, rows_per_page, current_page)

        # Display the paginated table
        event = st.dataframe(
            paginated_df,
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            column_config={
                "id": st.column_config.TextColumn("ID"),  # Add ID column config
                "Status": st.column_config.TextColumn("Status"),
                "threat_level": st.column_config.TextColumn("Threat Level"),
                "page_like_count": st.column_config.NumberColumn("Page Likes"),
                "report_count": st.column_config.NumberColumn("Reports"),
                "Reported": st.column_config.TextColumn("Reported"),
                "ad_url": st.column_config.LinkColumn("Ad URL", display_text="View Ad"),
            },
        )

        # Show pagination controls
        show_pagination_controls(len(display_df), rows_per_page, current_page)

        # Handle row selection
        if event.selection.rows:
            selected_row_index = event.selection.rows[0]
            # Get the selected row from the paginated dataframe
            selected_paginated_row = paginated_df.iloc[selected_row_index]

            # Get the ID from the selected row
            selected_id = (
                selected_paginated_row.get("id")
                if "id" in selected_paginated_row
                else None
            )

            if selected_id:
                # Find the corresponding row in the original df using the ID
                matching_row = df[df["id"] == selected_id]
                if not matching_row.empty:
                    selected_row_data = matching_row.iloc[0].to_dict()
                    st.session_state.selected_row_id = selected_id

                    # Show detailed view immediately
                    show_detailed_view(selected_row_data)
                else:
                    st.error(f"Could not find data for selected ID: {selected_id}")
            else:
                st.error("Selected row does not have an ID")
        else:
            st.markdown(
                """
                <div class='placeholder-panel'>
                    <strong>No ad selected.</strong><br/>
                    Use the table above to select an ad and reveal its detailed intelligence profile: red flags, patterns, links, and actionable recommendations.<br/>
                    <em>Tip:</em> Sort by Threat Level or Reports to prioritize high‑risk items first.
                </div>
                """,
                unsafe_allow_html=True,
            )

    else:
        st.warning("No data columns found to display.")

else:
    st.info("Click 'Refresh Data' to load the latest scam detection data.")

    # Show sample data structure
    st.subheader("📋 Expected Data Structure")
    st.code(
        """
    {
        "id": "unique_identifier",
        "page_name": "Page Name",
        "is_scam": true/false,
        "scam_type": "SCAM, SPAM, etc.",
        "threat_level": "HIGH/MEDIUM/LOW",
        "explanation": "Analysis explanation",
        "summary": ["Key findings"],
        "links_found": ["URLs found"],
        "scam_patterns": ["Patterns identified"],
        "red_flags": ["Red flags detected"],
        "recommendations": ["Recommended actions"]
    }
    """
    )

# Footer
st.markdown("---")
st.markdown(
    "**🛡️ Scam Detection Dashboard** | Built with Streamlit | For Law Enforcement Use"
)
