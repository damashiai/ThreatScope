import warnings

import streamlit as st
import pandas as pd
import plotly.express as px
from database import get_latest_threats

warnings.filterwarnings("ignore", message=".*country names.*", category=DeprecationWarning)

# --- Page Configuration ---
st.set_page_config(page_title="ThreatScope Dashboard", layout="wide", initial_sidebar_state="expanded")

# --- Header ---
st.title("ThreatScope")
st.markdown("**Advanced Threat Intelligence Platform** | Global Monitoring Dashboard")

# --- Fetch Local Database Data ---
threats_data = get_latest_threats(500) 

if not threats_data:
    st.warning("No threat data found in the local database. Please ensure 'worker.py' is running.")
    st.stop()

# Convert the dictionary data back to a Pandas DataFrame
df = pd.DataFrame(threats_data)

df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

# --- Top Level Metrics ---
st.markdown("### System Overview")
col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Monitored Threats", len(df))
col2.metric("Critical Alerts", len(df[df['severity'] == 'Critical']))
col3.metric("Average Threat Score", round(df['threat_score'].mean(), 1))

top_country = df[df['country'] != 'Unknown']['country'].value_counts().idxmax() if not df[df['country'] != 'Unknown'].empty else "Unknown"
col4.metric("Top Known Threat Origin", top_country)
col5.metric("Unique ISPs Tracked", df['isp'].nunique())

st.divider()

# --- First Row: Visualizations ---
col_map, col_pie = st.columns([2, 1])

with col_map:
    st.markdown("### Global Threat Origins")
    country_counts = df['country'].value_counts().reset_index()
    country_counts.columns = ['country', 'count']
    
    fig_map = px.choropleth(
        country_counts, 
        locations="country", 
        locationmode="country names",
        color="count",
        hover_name="country",
        color_continuous_scale="Reds",
    )
    fig_map.update_layout(margin={"r":0,"t":0,"l":0,"b":0}, geo=dict(bgcolor='rgba(0,0,0,0)'))
    
    # Updated to width='stretch' to fix the Streamlit warning
    st.plotly_chart(fig_map, width='stretch')

with col_pie:
    st.markdown("### Threat Classification")
    type_counts = df['type'].value_counts().reset_index()
    type_counts.columns = ['type', 'count']
    
    fig_pie = px.pie(type_counts, values='count', names='type', hole=0.4)
    fig_pie.update_layout(margin={"r":0,"t":0,"l":0,"b":0}, showlegend=False) 
    
    st.plotly_chart(fig_pie, width='stretch')

# --- Second Row: Operational Telemetry (New Data) ---
st.markdown("### Operational Telemetry")
col_time, col_isp = st.columns([2, 1])

with col_time:
    st.markdown("**Threat Detection Volume (Timeline)**")
    
    if not df['timestamp'].isnull().all():
        time_df = df.dropna(subset=['timestamp']).copy()
        time_df['Date'] = time_df['timestamp'].dt.date
        
        latest_entry = time_df['Date'].max()
        cutoff_date = latest_entry - pd.Timedelta(days=60)
        
        # Filter the data
        filtered_time_df = time_df[time_df['Date'] >= cutoff_date]
        
        # Aggregate and Sort
        daily_counts = filtered_time_df.groupby('Date').size().reset_index(name='Threats Detected')
        daily_counts = daily_counts.sort_values('Date')
        
        if not daily_counts.empty:
            fig_time = px.area(
                daily_counts, 
                x='Date', 
                y='Threats Detected', 
                color_discrete_sequence=['#ef4444'],
                line_shape='spline' 
            )
            
            # Clean up the styling
            fig_time.update_traces(line=dict(width=3), fillcolor='rgba(239, 68, 68, 0.2)')
            fig_time.update_layout(
                margin={"r":0,"t":10,"l":0,"b":0}, 
                xaxis_title=None,
                yaxis_title=None,
                xaxis=dict(showgrid=False, tickformat="%b %d"),
                yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)')
            )
            
            st.plotly_chart(fig_time, width='stretch')
        else:
            st.info("No recent telemetry data available within the 60-day window.")
    else:
        st.info("Insufficient timestamp data for time series.")

with col_isp:
    st.markdown("**Top Abused Hosting Providers**")
    known_isps = df[df['isp'] != 'Unknown']
    isp_counts = known_isps['isp'].value_counts().head(5).reset_index()
    isp_counts.columns = ['isp', 'count']
    
    fig_bar = px.bar(isp_counts, x='count', y='isp', orientation='h', color_discrete_sequence=['#f97316'])
    fig_bar.update_layout(margin={"r":0,"t":10,"l":0,"b":0}, yaxis={'categoryorder':'total ascending'}, yaxis_title=None, xaxis_title="Volume")
    
    # Updated to width='stretch'
    st.plotly_chart(fig_bar, width='stretch')

st.divider()

# --- Interactive Data Table ---
st.markdown("### Live Intelligence Feed")

f_col1, f_col2, f_col3 = st.columns(3)
with f_col1:
    severity_filter = st.multiselect("Filter by Severity", options=df['severity'].dropna().unique(), default=df['severity'].dropna().unique())
with f_col2:
    type_filter = st.multiselect("Filter by Type", options=df['type'].dropna().unique(), default=df['type'].dropna().unique())
with f_col3:
    source_filter = st.multiselect("Filter by Source", options=df['source'].dropna().unique(), default=df['source'].dropna().unique())

# Apply all three filters
filtered_df = df[
    (df['severity'].isin(severity_filter)) & 
    (df['type'].isin(type_filter)) &
    (df['source'].isin(source_filter))
]

display_cols = ['id', 'source', 'indicator', 'type', 'severity', 'threat_score', 'country', 'isp']

# Updated to width='stretch'
st.dataframe(filtered_df[display_cols], width='stretch', hide_index=True)