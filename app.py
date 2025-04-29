import json
import io
import streamlit as st
from google.oauth2 import service_account
from googleapiclient.discovery import build
import pandas as pd
import streamlit.components.v1 as components  # NEW

# --- Must be first Streamlit call ---
st.set_page_config(page_title="GSC URL Indexing Tool", layout="wide")

# --- Cached Helpers ---
@st.cache_data(show_spinner=False)
def get_credentials(file) -> service_account.Credentials:
    info = json.loads(file.getvalue().decode())
    scopes = [
        "https://www.googleapis.com/auth/webmasters",
        "https://www.googleapis.com/auth/indexing"
    ]
    return service_account.Credentials.from_service_account_info(info, scopes=scopes)

@st.cache_data(show_spinner=False)
def init_searchconsole_client(_creds):
    return build("searchconsole", "v1", credentials=_creds)

@st.cache_data(show_spinner=False)
def init_indexing_client(_creds):
    return build("indexing", "v3", credentials=_creds)

@st.cache_data(show_spinner=False)
def load_urls(file) -> pd.DataFrame:
    lines = file.getvalue().decode().splitlines()
    urls = [u.strip() for u in lines if u.strip()]
    return pd.DataFrame({"url": urls})

# --- Sidebar ---
st.sidebar.title("🔧 Settings")

creds_file = st.sidebar.file_uploader(
    "Service Account JSON",
    type="json",
    help="Download from GCP IAM & Admin → Service Accounts → Keys → Create Key → JSON"
)

property_options = []
property_url = None

if creds_file:
    creds = get_credentials(creds_file)
    sc_service = init_searchconsole_client(creds)
    try:
        resp = sc_service.sites().list().execute()
        property_options = [e["siteUrl"] for e in resp.get("siteEntry", [])]
    except Exception as e:
        st.sidebar.error(f"Failed to fetch properties: {e}")

    if "property_url" not in st.session_state:
        st.session_state.property_url = None

    if property_options:
        sorted_opts = sorted(property_options)
        default_idx = (
            sorted_opts.index(st.session_state.property_url)
            if st.session_state.property_url in sorted_opts
            else 0
        )
        sel = st.sidebar.selectbox(
            "Select Search Console Property",
            options=sorted_opts,
            index=default_idx
        )
        st.session_state.property_url = sel
        property_url = sel
    else:
        manual = st.sidebar.text_input(
            "Property URL (e.g. https://example.com or sc-domain:example.com)",
            key="manual_prop"
        )
        if manual:
            st.session_state.property_url = manual
        property_url = st.session_state.property_url

else:
    st.sidebar.info("Upload Service Account JSON first.")
    manual = st.sidebar.text_input(
        "Property URL (e.g. https://example.com or sc-domain:example.com)",
        key="manual_prop"
    )
    if manual:
        st.session_state.property_url = manual
    property_url = st.session_state.get("property_url")

uploaded_txt = st.sidebar.file_uploader(
    "Upload URL list (.txt)",
    type="txt",
    help="Newline-separated URLs"
)

auto_refresh = st.sidebar.checkbox("Auto-refresh inspection on upload", value=True)

# --- Sidebar: Start New Check ---
st.sidebar.markdown("---")
st.sidebar.subheader("🔁 Session Control")

confirm_reset = st.sidebar.checkbox("Confirm reset app state")
if st.sidebar.button("🔁 Start New Check"):
    if confirm_reset:
        # Force a full page reload
        components.html("""
            <script>
                window.location.reload();
            </script>
        """)
    else:
        st.sidebar.warning("Please confirm before resetting.")

# --- Main App Tabs ---
tab1, tab2 = st.tabs(["🔍 Index Checker", "🚀 Submit for Indexing"])

# --- TAB 1: Index Checker ---
with tab1:
    st.title("🔍 GSC URL Index Checker")

    if not creds_file:
        st.error("🔑 Upload your Service Account JSON.")
        st.stop()
    if not property_url:
        st.warning("Select or enter your Search Console property.")
        st.stop()
    if not uploaded_txt:
        st.info("📂 Upload a .txt file of URLs to get started.")
        st.stop()

    creds       = get_credentials(creds_file)
    sc_service  = init_searchconsole_client(creds)
    idx_service = init_indexing_client(creds)
    df          = load_urls(uploaded_txt)

    if "inspected_file" not in st.session_state or st.session_state.inspected_file != uploaded_txt.name:
        st.session_state.inspected = False
        st.session_state.inspected_file = uploaded_txt.name

    if auto_refresh and not st.session_state.inspected:
        with st.spinner("Inspecting URL index status..."):
            statuses, times = [], []
            for url in df["url"]:
                try:
                    req = {"inspectionUrl": url, "siteUrl": property_url}
                    resp = sc_service.urlInspection().index().inspect(body=req).execute()
                    res = resp.get("inspectionResult", {}).get("indexStatusResult", {})
                    statuses.append(res.get("coverageState", "UNKNOWN"))
                    times.append(res.get("lastCrawlTime", ""))
                except Exception as e:
                    err = str(e).splitlines()[0]
                    statuses.append(f"ERROR: {err}")
                    times.append("")
            df["Status"] = statuses
            df["Last Checked"] = times
            st.session_state.inspected = True
            st.session_state.df = df

    elif "df" in st.session_state:
        df = st.session_state.df
    else:
        st.warning("Please inspect URLs first.")
        st.stop()

    st.subheader("Index Status Results")
    st.dataframe(df, use_container_width=True)

    if st.button("🔄 Re-check Statuses"):
        st.session_state.inspected = False
        st.experimental_rerun()

# --- TAB 2: Submission ---
with tab2:
    st.title("🚀 Submit for Indexing")

    if "df" not in st.session_state:
        st.warning("Please inspect URLs in the first tab.")
        st.stop()

    df = st.session_state.df
    candidates = df[df["Status"] != "Submitted and indexed"]["url"].tolist()

    if not candidates:
        st.info("No URLs to submit — all are already indexed.")
        st.stop()

    if "to_submit" not in st.session_state:
        st.session_state.to_submit = []

    selected_urls = st.multiselect(
        "Select URLs to submit:",
        options=candidates,
        default=st.session_state.to_submit,
        key="urls_to_submit"
    )
    st.session_state.to_submit = selected_urls

    if selected_urls:
        st.subheader("Ready to Submit")
        st.dataframe(pd.DataFrame({"Selected URLs": selected_urls}))
    else:
        st.info("No URLs selected for indexing.")
        st.stop()

    if st.button("✅ Submit Selected URLs"):
        creds = get_credentials(creds_file)
        idx_service = init_indexing_client(creds)
        successes, errors = [], []

        with st.spinner("Submitting selected URLs..."):
            for url in selected_urls:
                try:
                    idx_service.urlNotifications().publish(
                        body={"url": url, "type": "URL_UPDATED"}
                    ).execute()
                    successes.append(url)
                except Exception as e:
                    errors.append((url, str(e)))

        if successes:
            st.success(f"✅ {len(successes)} URLs submitted!")
            df_sub = pd.DataFrame({"submitted_url": successes})
            buf = io.BytesIO()
            df_sub.to_excel(buf, index=False, sheet_name="Submitted")
            buf.seek(0)
            st.download_button(
                "📥 Download submitted URLs",
                data=buf,
                file_name="submitted_urls.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

        for url, msg in errors:
            st.error(f"❌ {url}: {msg}")
