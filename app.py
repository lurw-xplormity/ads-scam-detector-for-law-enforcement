import streamlit as st
import requests
import pandas as pd
import os
import plotly.express as px
import plotly.graph_objects as go
import math

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
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
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
    st.session_state.rows_per_page = 10

# Header
st.markdown(
    '<h1 class="main-header">🛡️ Scam Detection Dashboard</h1>', unsafe_allow_html=True
)

# Sidebar
with st.sidebar:
    st.header("🔧 Controls")

    # Add info note about crawler schedule
    st.info("📅 **Note:** The crawler automatically scrapes new data every week to keep the database updated with the latest ads.")

    # Refresh data button
    if st.button("🔄 Refresh Data", type="primary"):
        with st.spinner("Fetching latest data..."):
            try:
                response = requests.get(
                    MAIN_URL
                )
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
        index=1,  # Default to 10
        key="rows_per_page_selector",
    )
    st.session_state.rows_per_page = rows_per_page

    # Filters
    st.header("🔍 Filters")

    if st.session_state.data:
        df = pd.DataFrame(st.session_state.data)

        # Scam filter
        scam_filter = st.selectbox(
            "Filter by Scam Status", ["All", "Scam Only", "Legit Only"]
        )

        # Threat level filter
        threat_levels = (
            df["threat_level"].unique() if "threat_level" in df.columns else []
        )
        threat_filter = st.multiselect(
            "Filter by Threat Level", threat_levels, default=threat_levels
        )

        # Date range filter
        if "date_scraped" in df.columns:
            df["date_scraped"] = pd.to_datetime(df["date_scraped"])
            date_range = st.date_input(
                "Date Range",
                value=(
                    df["date_scraped"].min().date(),
                    df["date_scraped"].max().date(),
                ),
                min_value=df["date_scraped"].min().date(),
                max_value=df["date_scraped"].max().date(),
            )


# Main content
def load_initial_data():
    """Load data on app start"""
    if st.session_state.data is None:
        with st.spinner("Loading initial data..."):
            try:
                response = requests.get(
                    MAIN_URL
                )
                if response.status_code == 200:
                    res_data = response.json()
                    st.session_state.data = res_data.get("data", [])
                else:
                    st.error(
                        f"Failed to load data. Status code: {response.status_code}"
                    )
                    return None
            except Exception as e:
                st.error(f"Error loading data: {str(e)}")
                return None
    return st.session_state.data


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


def show_detailed_view(row_data):
    """Show detailed view of selected row"""
    st.header("📋 Detailed View")

    # Add Report to Police button at the top
    col1, col2 = st.columns([1, 1])
    with col1:
        st.write(f"**Selected ID:** {row_data.get('id', 'N/A')}")

    with col2:
        if row_data.get("reported") == 1:
            st.markdown(
                '<span class="legit-badge">✓ Already Reported</span>',
                unsafe_allow_html=True,
            )
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
        st.text_area("Ad Text", value=row_data["ad_text"], height=100, disabled=True)

    # Explanation
    if row_data.get("explanation"):
        st.subheader("💡 Analysis Explanation")
        st.write(row_data["explanation"])

    # Summary
    if row_data.get("summary"):
        st.subheader("📋 Summary")
        summary_list = (
            row_data["summary"]
            if isinstance(row_data["summary"], list)
            else [row_data["summary"]]
        )
        for item in summary_list:
            st.write(f"• {item}")

    # Links Found
    if row_data.get("links_found"):
        st.subheader("🔗 Links Found")
        links = (
            row_data["links_found"]
            if isinstance(row_data["links_found"], list)
            else [row_data["links_found"]]
        )
        for link in links:
            st.write(f"• {link}")

    # Scam Patterns
    if row_data.get("scam_patterns"):
        st.subheader("🔍 Scam Patterns")
        patterns = (
            row_data["scam_patterns"]
            if isinstance(row_data["scam_patterns"], list)
            else [row_data["scam_patterns"]]
        )
        for pattern in patterns:
            st.write(f"• {pattern}")

    # Red Flags
    if row_data.get("red_flags"):
        st.subheader("🚩 Red Flags")
        flags = (
            row_data["red_flags"]
            if isinstance(row_data["red_flags"], list)
            else [row_data["red_flags"]]
        )
        for flag in flags:
            st.write(f"• {flag}")

    # Recommendations
    if row_data.get("recommendations"):
        st.subheader("💼 Recommendations")
        recommendations = (
            row_data["recommendations"]
            if isinstance(row_data["recommendations"], list)
            else [row_data["recommendations"]]
        )
        for rec in recommendations:
            st.write(f"• {rec}")

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


# Load data
data = load_initial_data()

if data:
    df = pd.DataFrame(data)

    # Ensure ID column is string type to avoid Arrow serialization issues
    if "id" in df.columns:
        df["id"] = df["id"].astype(str)
    
    # Convert numeric columns to proper types, handling errors
    if "page_like_count" in df.columns:
        df["page_like_count"] = pd.to_numeric(df["page_like_count"], errors='coerce').fillna(0).astype(int)
    
    if "report_count" in df.columns:
        df["report_count"] = pd.to_numeric(df["report_count"], errors='coerce').fillna(0).astype(int)
    
    if "reported" in df.columns:
        df["reported"] = pd.to_numeric(df["reported"], errors='coerce').fillna(0).astype(int)


    # Apply filters
    if "scam_filter" in locals():
        if scam_filter == "Scam Only":
            df = df[df["is_scam"] == True]
        elif scam_filter == "Legit Only":
            df = df[df["is_scam"] == False]

    if "threat_filter" in locals() and threat_filter:
        df = df[df["threat_level"].isin(threat_filter)]

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
        reported_count = (
            len(df[df["reported"] == 1]) if "reported" in df.columns else 0
        )
        st.metric("📮 Reported", reported_count)

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
                threat_counts = df["threat_level"].value_counts()
                fig_bar = px.bar(
                    x=threat_counts.index,
                    y=threat_counts.values,
                    title="Threat Level Distribution",
                    color=threat_counts.index,
                    color_discrete_map={
                        "HIGH": "#ff4b4b",
                        "MEDIUM": "#ffa500",
                        "LOW": "#00cc88",
                    },
                )
                st.plotly_chart(fig_bar, use_container_width=True)

    # Main data table with pagination
    st.header("📋 Ads Overview")

    # Select important columns for the main table
    important_columns = [
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

        # Format the display
        if "is_scam" in display_df.columns:
            display_df["Status"] = display_df["is_scam"].apply(
                lambda x: "SCAM" if x else "LEGIT"
            )
            display_df = display_df.drop("is_scam", axis=1)

        # Format reported column with tick/cross
        if "reported" in display_df.columns:
            display_df["Reported"] = display_df["reported"].apply(
                lambda x: "✅" if x == 1 else "❌"
            )
            display_df = display_df.drop("reported", axis=1)

        # Paginate the data
        current_page = st.session_state.current_page
        rows_per_page = st.session_state.rows_per_page

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
                "Reported": st.column_config.TextColumn("Reported"),  # Configure reported column
            },
        )

        # Show pagination controls
        show_pagination_controls(len(display_df), rows_per_page, current_page)

        # Handle row selection
        if event.selection.rows:
            selected_row_index = event.selection.rows[0]
            # Calculate the actual index in the original dataframe
            actual_index = (current_page - 1) * rows_per_page + selected_row_index
            selected_row_data = df.iloc[actual_index].to_dict()
            st.session_state.selected_row_id = selected_row_data.get("id")

            # Show detailed view immediately
            show_detailed_view(selected_row_data)

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
