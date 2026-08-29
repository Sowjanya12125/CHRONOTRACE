"""
dashboard.py
------------
Streamlit dashboard for the forensic timeline generator. Loads (or
regenerates) the timeline built by timeline_engine.py and gives an
investigator an interactive view: colored stat cards, a chart of
events over time, severity/event-type breakdown donuts, filters for
date range / severity / deleted-only / path search, a sortable table,
and CSV/JSON download of whatever's currently filtered.

Run with:
    streamlit run dashboard.py
"""

import hashlib
import io
import os
import tempfile

import pandas as pd
import streamlit as st
import altair as alt

from fat16_parser import Fat16Parser
from deleted_file_recovery import DeletedFileRecovery
from anomaly_detector import AnomalyDetector
from timeline_engine import generate_timeline

st.set_page_config(page_title="FFSTG — Forensic Timeline", layout="wide",
                    initial_sidebar_state="expanded")

# =======================================================================
# Theme
# =======================================================================

THEMES = {
    "Light": dict(
        bg="#F5F6FA", card="#FFFFFF", text="#1A1D29", muted="#6B7280",
        border="#E8E9F0", sidebar_bg="#15162B", sidebar_text="#E4E5F1",
        sidebar_muted="#8B8DA8", accent="#6C5CE7", shadow="0 2px 12px rgba(20,20,50,0.06)",
    ),
    "Dark": dict(
        bg="#0F1020", card="#1A1B30", text="#F0F1FA", muted="#9698B8",
        border="#2A2C48", sidebar_bg="#0A0B18", sidebar_text="#E4E5F1",
        sidebar_muted="#7B7DA0", accent="#8B7CFF", shadow="0 2px 16px rgba(0,0,0,0.35)",
    ),
}

ICONS = {
    "events": '<path d="M6 2h9l5 5v15H6z"/><path d="M15 2v5h5" fill="none" stroke-width="1.5"/><line x1="9" y1="13" x2="17" y2="13" stroke-width="1.5"/><line x1="9" y1="17" x2="17" y2="17" stroke-width="1.5"/>',
    "files": '<path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    "deleted": '<path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13" fill="none" stroke-width="1.6"/>',
    "alert": '<path d="M12 2 1 21h22z"/><line x1="12" y1="9" x2="12" y2="14" stroke="white" stroke-width="1.6"/><circle cx="12" cy="17" r="1" fill="white"/>',
}


def inject_css(theme):
    t = THEMES[theme]
    st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"] {{ font-family: 'Inter', sans-serif; }}

    .stApp {{ background: {t['bg']}; }}
    [data-testid="stHeader"] {{ background: transparent; }}
    .block-container {{ padding-top: 2rem; max-width: 1200px; }}

    /* Sidebar */
    [data-testid="stSidebar"] {{
        background: {t['sidebar_bg']};
    }}
    [data-testid="stSidebar"] * {{ color: {t['sidebar_text']}; }}
    [data-testid="stSidebar"] label, [data-testid="stSidebar"] .stCaption {{
        color: {t['sidebar_muted']} !important;
    }}
    [data-testid="stSidebar"] input, [data-testid="stSidebar"] textarea {{
        background: rgba(255,255,255,0.06) !important;
        color: {t['sidebar_text']} !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        border-radius: 8px !important;
    }}
    [data-testid="stSidebar"] [data-baseweb="select"] > div {{
        background: rgba(255,255,255,0.06) !important;
        border-color: rgba(255,255,255,0.1) !important;
        border-radius: 8px !important;
    }}
    [data-testid="stSidebar"] hr {{ border-color: rgba(255,255,255,0.08); }}

    .brand-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }}
    .brand-icon {{
        width: 34px; height: 34px; border-radius: 9px;
        background: linear-gradient(135deg, {t['accent']}, #A084FF);
        display: flex; align-items: center; justify-content: center;
        font-size: 17px; flex-shrink: 0;
    }}
    .brand-title {{ font-size: 17px; font-weight: 800; color: {t['sidebar_text']}; letter-spacing: -0.3px; }}
    .brand-sub {{ font-size: 11.5px; color: {t['sidebar_muted']}; margin: 0 0 18px 44px; }}
    .side-heading {{
        font-size: 11px; font-weight: 700; letter-spacing: 0.08em;
        color: {t['sidebar_muted']}; text-transform: uppercase;
        margin: 18px 0 8px 2px;
    }}

    /* Header / badge */
    .page-title {{ font-size: 32px; font-weight: 800; color: {t['text']}; letter-spacing: -0.5px; margin-bottom: 2px; }}
    .page-sub {{ color: {t['muted']}; font-size: 14.5px; margin-bottom: 14px; }}
    .status-pill {{
        display: inline-flex; align-items: center; gap: 6px;
        background: rgba(46, 204, 113, 0.14); color: #27AE60;
        padding: 5px 14px; border-radius: 20px; font-size: 12.5px; font-weight: 600;
    }}
    .status-pill.err {{ background: rgba(231, 76, 60, 0.14); color: #E74C3C; }}
    .dot {{ width: 7px; height: 7px; border-radius: 50%; background: currentColor; display: inline-block; }}

    .section-label {{
        font-size: 11.5px; font-weight: 700; letter-spacing: 0.08em;
        color: {t['muted']}; text-transform: uppercase; margin: 28px 0 12px 0;
    }}

    /* Stat cards */
    .stat-card {{
        background: {t['card']}; border-radius: 14px; padding: 18px 20px 16px 20px;
        box-shadow: {t['shadow']}; border-top: 3px solid var(--accent-color);
        height: 100%;
    }}
    .stat-icon {{
        width: 34px; height: 34px; border-radius: 9px;
        background: color-mix(in srgb, var(--accent-color) 16%, transparent);
        display: flex; align-items: center; justify-content: center; margin-bottom: 12px;
    }}
    .stat-num {{ font-size: 28px; font-weight: 800; color: {t['text']}; letter-spacing: -0.5px; line-height: 1.1; }}
    .stat-label {{ font-size: 13px; color: {t['muted']}; margin-top: 2px; font-weight: 500; }}

    /* Card container (charts/table) */
    div[data-testid="stVerticalBlockBorderWrapper"] {{
        background: {t['card']}; border-radius: 16px !important;
        box-shadow: {t['shadow']}; border: 1px solid {t['border']} !important;
        padding: 6px;
    }}
    .card-title {{ font-size: 15.5px; font-weight: 700; color: {t['text']}; margin: 6px 0 2px 4px; }}
    .card-sub {{ font-size: 12.5px; color: {t['muted']}; margin: 0 0 10px 4px; }}

    [data-testid="stMetricValue"] {{ color: {t['text']}; }}
    .stDataFrame {{ border-radius: 10px; overflow: hidden; }}

    [data-testid="stSegmentedControl"] label {{ color: {t['text']} !important; }}
    </style>
    """, unsafe_allow_html=True)


def stat_card(icon_key, color, number, label):
    svg = (f'<svg width="17" height="17" viewBox="0 0 24 24" fill="{color}" '
           f'stroke="{color}" stroke-linejoin="round">{ICONS[icon_key]}</svg>')
    st.markdown(f"""
    <div class="stat-card" style="--accent-color:{color}">
        <div class="stat-icon">{svg}</div>
        <div class="stat-num">{number}</div>
        <div class="stat-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)


# =======================================================================
# Data loading
# =======================================================================

@st.cache_data(show_spinner="Parsing image and building timeline...")
def load_timeline(image_path, acquisition_time, content_hash=None):
    # content_hash is unused inside the function but is part of the cache
    # key, so re-uploading a different file with the same temp filename
    # doesn't serve stale cached results.
    parser = Fat16Parser(image_path)
    live_records = [r for r in parser.walk() if not r.name.startswith("$")]

    detector = AnomalyDetector(acquisition_time=acquisition_time)
    anomalies = detector.scan(live_records)

    recovery = DeletedFileRecovery(image_path)
    deleted_records = recovery.scan()

    events = generate_timeline(live_records, deleted_records, anomalies)
    df = pd.DataFrame([e.to_dict() for e in events])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def donut_chart(df_counts, field, color_range, domain):
    return (
        alt.Chart(df_counts)
        .mark_arc(innerRadius=55, outerRadius=90)
        .encode(
            theta=alt.Theta("count:Q"),
            color=alt.Color(f"{field}:N",
                             scale=alt.Scale(domain=domain, range=color_range),
                             legend=alt.Legend(title=None, orient="right")),
            tooltip=[field, "count"],
        )
        .properties(height=230)
    )


# =======================================================================
# App
# =======================================================================

def main():
    if "theme" not in st.session_state:
        st.session_state["theme"] = "Light"

    with st.sidebar:
        st.markdown("""
        <div class="brand-row">
            <div class="brand-icon">🔎</div>
            <div class="brand-title">FFSTG</div>
        </div>
        <div class="brand-sub">Forensic File System Timeline</div>
        """, unsafe_allow_html=True)

        theme = st.segmented_control("Theme", options=["Light", "Dark"],
                                      default=st.session_state["theme"], label_visibility="collapsed")
        if theme:
            st.session_state["theme"] = theme

        st.markdown('<div class="side-heading">Evidence</div>', unsafe_allow_html=True)
        uploaded_file = st.file_uploader(
            "Upload disk image", type=None,
            help="Raw disk/partition image — .dd, .img, .raw, .001, etc. "
                 "Large images may need a higher upload limit (see note below).",
        )
        st.caption("— or —")
        typed_path = st.text_input(
            "Disk image path (.dd)", value="" if uploaded_file else "test_disk.dd",
            placeholder="…or type a path already on this machine",
        )

        content_hash = None
        if uploaded_file is not None:
            file_bytes = uploaded_file.getvalue()
            content_hash = hashlib.md5(file_bytes).hexdigest()[:16]
            image_path = os.path.join(
                tempfile.gettempdir(), f"ffstg_upload_{content_hash}.dd")
            if not os.path.exists(image_path):
                with open(image_path, "wb") as f:
                    f.write(file_bytes)
            source_label = f"{uploaded_file.name} ({len(file_bytes) / (1024*1024):.1f} MB)"
        else:
            image_path = typed_path
            source_label = typed_path or "(no image selected)"

        st.caption(f"Source: {source_label}")

        acquisition_date = st.date_input("Acquisition date")
        acquisition_time = pd.Timestamp(acquisition_date).to_pydatetime()

    inject_css(st.session_state["theme"])

    if not image_path:
        st.info("Upload a disk image or enter a path in the sidebar to begin.")
        st.stop()

    try:
        df = load_timeline(image_path, acquisition_time, content_hash)
        load_error = None
    except Exception as e:
        df = None
        load_error = str(e)

    st.markdown('<div class="page-title">Forensic File System Timeline</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-sub">Digital Forensics &amp; Incident Response</div>', unsafe_allow_html=True)
    if load_error:
        st.markdown('<span class="status-pill err"><span class="dot"></span> Load failed</span>',
                     unsafe_allow_html=True)
        st.error(f"Couldn't open/parse image: {load_error}")
        st.stop()
    else:
        st.markdown('<span class="status-pill"><span class="dot"></span> Evidence Loaded</span>',
                     unsafe_allow_html=True)

    with st.sidebar:
        st.markdown('<div class="side-heading">Filters</div>', unsafe_allow_html=True)
        search = st.text_input("Search path contains", placeholder="Search path contains…")

        min_ts, max_ts = df["timestamp"].min(), df["timestamp"].max()
        if min_ts == max_ts:
            date_range = (min_ts.to_pydatetime(), max_ts.to_pydatetime())
        else:
            date_range = st.slider(
                "Date range",
                min_value=min_ts.to_pydatetime(), max_value=max_ts.to_pydatetime(),
                value=(min_ts.to_pydatetime(), max_ts.to_pydatetime()),
            )

        event_types = st.multiselect(
            "Event type", options=["created", "modified", "accessed"],
            default=["created", "modified", "accessed"],
        )

        severities = st.multiselect(
            "Anomaly severity", options=["HIGH", "MEDIUM", "LOW"],
            default=["HIGH", "MEDIUM", "LOW"],
        )

        deleted_filter = st.radio(
            "Deleted files", options=["All", "Deleted only", "Live only"], index=0,
        )

    # ------------------------------------------------------------
    # apply filters
    # ------------------------------------------------------------
    filtered = df[
        (df["timestamp"] >= date_range[0]) & (df["timestamp"] <= date_range[1])
    ]
    if search:
        filtered = filtered[filtered["path"].str.contains(search, case=False)]
    if event_types:
        filtered = filtered[filtered["event_type"].isin(event_types)]
    if deleted_filter == "Deleted only":
        filtered = filtered[filtered["deleted"]]
    elif deleted_filter == "Live only":
        filtered = filtered[~filtered["deleted"]]

    if set(severities) != {"HIGH", "MEDIUM", "LOW"}:
        filtered = filtered[filtered["severity"].isin(severities)]

    # ------------------------------------------------------------
    # stat cards
    # ------------------------------------------------------------
    st.markdown('<div class="section-label">Evidence Status</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        stat_card("events", "#5B6EE1", len(filtered), "Total events")
    with c2:
        stat_card("files", "#27AE60", filtered["path"].nunique(), "Unique files")
    with c3:
        stat_card("deleted", "#E74C3C", filtered[filtered["deleted"]]["path"].nunique(), "Deleted files")
    with c4:
        stat_card("alert", "#F2A93B", int(filtered["severity"].notna().sum()), "Anomalies flagged")

    # ------------------------------------------------------------
    # interactive timeline chart
    # ------------------------------------------------------------
    st.markdown('<div class="section-label">Timeline Analysis</div>', unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown('<div class="card-title">Event Timeline</div>', unsafe_allow_html=True)
        st.markdown('<div class="card-sub">Every MAC timestamp, plotted per file</div>', unsafe_allow_html=True)
        if filtered.empty:
            st.info("No events match the current filters.")
        else:
            color_field = alt.condition(
                "datum.deleted == true",
                alt.value("#E74C3C"),
                alt.Color("severity:N",
                          scale=alt.Scale(domain=["HIGH", "MEDIUM", "LOW"],
                                           range=["#E74C3C", "#F2A93B", "#5B6EE1"]),
                          legend=alt.Legend(title="Severity")),
            )
            chart = (
                alt.Chart(filtered)
                .mark_circle(size=90)
                .encode(
                    x=alt.X("timestamp:T", title="Time"),
                    y=alt.Y("path:N", title="File", sort="-x"),
                    color=color_field,
                    shape=alt.Shape("event_type:N", title="Event"),
                    tooltip=["timestamp", "event_type", "path", "size",
                             "deleted", "severity", "anomaly_rule"],
                )
                .properties(height=max(280, 24 * filtered["path"].nunique()))
                .configure_axis(grid=True, gridOpacity=0.15)
                .configure_view(strokeWidth=0)
                .interactive()
            )
            st.altair_chart(chart, width="stretch")

    # ------------------------------------------------------------
    # donut breakdowns
    # ------------------------------------------------------------
    d1, d2 = st.columns(2)
    with d1:
        with st.container(border=True):
            st.markdown('<div class="card-title">Severity Breakdown</div>', unsafe_allow_html=True)
            st.markdown('<div class="card-sub">Anomaly findings by severity</div>', unsafe_allow_html=True)
            sev_counts = (filtered[filtered["severity"].notna()]
                          .groupby("severity")["path"].nunique()
                          .reset_index(name="count"))
            if sev_counts.empty:
                st.info("No anomalies in the current filter selection.")
            else:
                st.altair_chart(
                    donut_chart(sev_counts, "severity", ["#E74C3C", "#F2A93B", "#5B6EE1"],
                                ["HIGH", "MEDIUM", "LOW"]),
                    width="stretch",
                )
    with d2:
        with st.container(border=True):
            st.markdown('<div class="card-title">Event Type Breakdown</div>', unsafe_allow_html=True)
            st.markdown('<div class="card-sub">Created / modified / accessed events</div>', unsafe_allow_html=True)
            type_counts = (filtered.groupby("event_type")["path"].count()
                           .reset_index(name="count"))
            if type_counts.empty:
                st.info("No events match the current filters.")
            else:
                st.altair_chart(
                    donut_chart(type_counts, "event_type",
                                ["#6C5CE7", "#27AE60", "#F2A93B"],
                                ["created", "modified", "accessed"]),
                    width="stretch",
                )

    # ------------------------------------------------------------
    # data table + export
    # ------------------------------------------------------------
    st.markdown('<div class="section-label">Events</div>', unsafe_allow_html=True)
    with st.container(border=True):
        st.dataframe(filtered.sort_values("timestamp"), width="stretch", hide_index=True)

        csv_buf = io.StringIO()
        filtered.to_csv(csv_buf, index=False)
        json_buf = filtered.to_json(orient="records", indent=2, date_format="iso")

        dl1, dl2 = st.columns(2)
        dl1.download_button("Download filtered CSV", csv_buf.getvalue(),
                             file_name="timeline_filtered.csv", mime="text/csv",
                             width="stretch")
        dl2.download_button("Download filtered JSON", json_buf,
                             file_name="timeline_filtered.json", mime="application/json",
                             width="stretch")


if __name__ == "__main__":
    main()