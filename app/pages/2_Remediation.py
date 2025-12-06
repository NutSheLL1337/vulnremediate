"""
Remediation Page - генерація рекомендацій для виправлення вразливостей
"""

import streamlit as st
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.remediation import RemediationEngine


def main():
    st.set_page_config(page_title="Remediation", page_icon="🔧", layout="wide")
    
    st.title("🔧 Vulnerability Remediation")
    st.markdown("Automated remediation recommendations based on scan results")
    
    # Ініціалізація remediation engine
    engine = RemediationEngine()
    
    # Знайти доступні скани
    scans_dir = Path(__file__).parent.parent.parent / "scans"
    
    if not scans_dir.exists():
        st.error("No scans directory found. Please run a scan first.")
        return
    
    # Отримати список сканів
    scan_folders = sorted(
        [d for d in scans_dir.iterdir() if d.is_dir()],
        key=lambda x: x.name,
        reverse=True
    )
    
    if not scan_folders:
        st.warning("No scans found. Please run a scan from the Scan page first.")
        return
    
    # Вибір скану
    st.sidebar.header("Select Scan")
    
    scan_options = {f.name: f for f in scan_folders}
    selected_scan_name = st.sidebar.selectbox(
        "Available Scans",
        options=list(scan_options.keys()),
        help="Select a scan to generate remediation recommendations"
    )
    
    selected_scan = scan_options[selected_scan_name]
    
    # Показати інформацію про скан
    config_file = selected_scan / "config.json"
    if config_file.exists():
        import json
        with open(config_file, encoding='utf-8') as f:
            config = json.load(f)
        
        st.sidebar.markdown("### Scan Details")
        st.sidebar.markdown(f"**Target:** {config.get('target_name', 'Unknown')}")
        st.sidebar.markdown(f"**Timestamp:** {config.get('timestamp', 'Unknown')}")
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("Remediation Recommendations")
    
    with col2:
        if st.button("🔄 Generate Remediations", type="primary", use_container_width=True):
            with st.spinner("Analyzing vulnerabilities and generating remediations..."):
                # Генерація remediation рекомендацій
                st.session_state.remediations = engine.analyze_scan_results(selected_scan)
                st.success(f"Generated {len(st.session_state.remediations)} remediation recommendations!")
    
    # Показати результати
    if 'remediations' in st.session_state and st.session_state.remediations:
        remediations = st.session_state.remediations
        
        # Summary metrics
        st.markdown("---")
        
        metrics_cols = st.columns(4)
        
        with metrics_cols[0]:
            st.metric("Total Vulnerabilities", len(remediations))
        
        with metrics_cols[1]:
            critical_count = sum(1 for r in remediations if r['severity'] == 'critical')
            st.metric("Critical", critical_count, delta=None if critical_count == 0 else "⚠️")
        
        with metrics_cols[2]:
            high_count = sum(1 for r in remediations if r['severity'] == 'high')
            st.metric("High", high_count)
        
        with metrics_cols[3]:
            # Unique types
            unique_types = len(set(r['type'] for r in remediations))
            st.metric("Vulnerability Types", unique_types)
        
        st.markdown("---")
        
        # Filters
        st.subheader("Filter Recommendations")
        
        filter_cols = st.columns(3)
        
        with filter_cols[0]:
            filter_source = st.multiselect(
                "Source",
                options=list(set(r['source'] for r in remediations)),
                default=list(set(r['source'] for r in remediations))
            )
        
        with filter_cols[1]:
            filter_severity = st.multiselect(
                "Severity",
                options=['critical', 'high', 'medium', 'low'],
                default=['critical', 'high', 'medium', 'low']
            )
        
        with filter_cols[2]:
            filter_type = st.multiselect(
                "Type",
                options=list(set(r['type'] for r in remediations)),
                default=list(set(r['type'] for r in remediations))
            )
        
        # Apply filters
        filtered_rems = [
            r for r in remediations
            if r['source'] in filter_source
            and r['severity'] in filter_severity
            and r['type'] in filter_type
        ]
        
        st.markdown(f"**Showing {len(filtered_rems)} of {len(remediations)} recommendations**")
        
        # Display remediations
        st.markdown("---")
        
        if not filtered_rems:
            st.info("No remediations match the current filters.")
        else:
            # Tabs для різних view modes
            view_mode = st.radio(
                "View Mode",
                ["Detailed View", "Summary Table"],
                horizontal=True
            )
            
            if view_mode == "Detailed View":
                # Detailed cards
                for idx, rem in enumerate(filtered_rems, 1):
                    # Severity badge color
                    severity_colors = {
                        'critical': '🔴',
                        'high': '🟠',
                        'medium': '🟡',
                        'low': '🟢',
                        'unknown': '⚪'
                    }
                    
                    badge = severity_colors.get(rem['severity'], '⚪')
                    
                    with st.expander(
                        f"{badge} {idx}. {rem['type'].replace('-', ' ').title()} - {rem['file']}",
                        expanded=(idx == 1)  # Перший expander відкритий
                    ):
                        # Metadata
                        meta_cols = st.columns(4)
                        with meta_cols[0]:
                            st.markdown(f"**Source:** `{rem['source']}`")
                        with meta_cols[1]:
                            st.markdown(f"**Severity:** `{rem['severity']}`")
                        with meta_cols[2]:
                            st.markdown(f"**Type:** `{rem['type']}`")
                        with meta_cols[3]:
                            st.markdown(f"**Line:** `{rem['line']}`")
                        
                        st.markdown("---")
                        
                        # Remediation content
                        st.markdown(rem['remediation'])
                        
                        # Download button
                        st.download_button(
                            label="📥 Download Remediation",
                            data=rem['remediation'],
                            file_name=f"remediation_{rem['type']}_{idx}.md",
                            mime="text/markdown",
                            key=f"download_{idx}"
                        )
            
            else:  # Summary Table
                # Create summary table
                import pandas as pd
                
                table_data = []
                for idx, rem in enumerate(filtered_rems, 1):
                    table_data.append({
                        '#': idx,
                        'Type': rem['type'].replace('-', ' ').title(),
                        'Severity': rem['severity'].upper(),
                        'Source': rem['source'].upper(),
                        'File': rem['file'].split('/')[-1] if '/' in rem['file'] else rem['file'],
                        'Line': rem['line']
                    })
                
                df = pd.DataFrame(table_data)
                
                # Color code severity
                def color_severity(val):
                    colors = {
                        'CRITICAL': 'background-color: #ff4444; color: white',
                        'HIGH': 'background-color: #ff8800; color: white',
                        'MEDIUM': 'background-color: #ffbb33; color: black',
                        'LOW': 'background-color: #00C851; color: white',
                    }
                    return colors.get(val, '')
                
                styled_df = df.style.applymap(color_severity, subset=['Severity'])
                
                st.dataframe(styled_df, use_container_width=True, height=400)
        
        # Export all remediations
        st.markdown("---")
        
        export_cols = st.columns([3, 1])
        
        with export_cols[0]:
            st.markdown("### Export Remediations")
            st.markdown("Download all remediation recommendations as a combined report")
        
        with export_cols[1]:
            # Generate combined report
            combined_report = "# Vulnerability Remediation Report\n\n"
            combined_report += f"**Scan:** {selected_scan_name}\n\n"
            combined_report += f"**Total Recommendations:** {len(filtered_rems)}\n\n"
            combined_report += "---\n\n"
            
            for idx, rem in enumerate(filtered_rems, 1):
                combined_report += f"## {idx}. {rem['type'].replace('-', ' ').title()}\n\n"
                combined_report += rem['remediation']
                combined_report += "\n\n---\n\n"
            
            st.download_button(
                label="📦 Export All",
                data=combined_report,
                file_name=f"remediation_report_{selected_scan_name}.md",
                mime="text/markdown",
                type="primary",
                use_container_width=True
            )
    
    else:
        # No remediations yet
        st.info("👆 Click 'Generate Remediations' to analyze vulnerabilities and create fix recommendations")
        
        # Show preview
        st.markdown("---")
        st.subheader("What to Expect")
        
        preview_cols = st.columns(3)
        
        with preview_cols[0]:
            st.markdown("### 🔍 Analysis")
            st.markdown("""
            The system will:
            - Parse scan results
            - Identify vulnerability types
            - Extract relevant context
            """)
        
        with preview_cols[1]:
            st.markdown("### 🔧 Generation")
            st.markdown("""
            For each vulnerability:
            - Detailed explanation
            - Code examples
            - Best practices
            """)
        
        with preview_cols[2]:
            st.markdown("### 📋 Templates")
            st.markdown("""
            Support for:
            - SQL Injection
            - XSS
            - Command Injection
            - Path Traversal
            - Hardcoded Credentials
            """)


if __name__ == "__main__":
    main()
