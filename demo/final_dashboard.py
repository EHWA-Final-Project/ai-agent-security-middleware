"""Unified Streamlit entry point; keeps the original Workbench available."""

from pathlib import Path

import streamlit as st

HERE = Path(__file__).resolve().parent
st.navigation([
    st.Page(str(HERE / "final_view.py"), title="연구 콘솔", default=True),
    st.Page(str(HERE / "dashboard.py"), title="Workbench · Fixture / Mock"),
], position="top").run()
