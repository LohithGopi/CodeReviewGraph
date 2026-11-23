"""Command Line Interface for CodeReviewGraph."""
import sys
import argparse
import uuid
from pathlib import Path
from codereviewgraph.graph.workflow import review_app


def print_report_summary(report: dict):
    """Format and print an ANSI summary to stdout."""
    score = report.get("health_score", 0)
    total = report.get("total_findings", 0)
    crits = report.get("critical_count", 0)
    highs = report.get("high_count", 0)
    
    print("\n" + "=" * 60)
    print("   CODEREVIEWGRAPH AUDIT RESULT")
    print("=" * 60)
    
    status_icon = "🟢" if score >= 85 else ("🟡" if score >= 50 else "🔴")
    print(f"Health Score: {status_icon} {score}/100")
    print(f"Total Findings: {total} (Critical: {crits}, High: {highs})")
    print("-" * 60)
    
    findings = report.get("findings", [])
    if not findings:
        print("✅ No issues detected. Code is clean and safe.")
    else:
        for f in findings:
            sev = f.get("severity", "INFO")
            print(f"• [{sev}] Line {f.get('line_number', '?')}: {f.get('title')}")
            print(f"  Remediation: {f.get('remediation')}")

    patches = report.get("patches", [])
    if patches:
        print("\n" + "-" * 60)
        print("🔧 AUTOMATED REMEDIATION PATCHES")
        print("-" * 60)
        for p in patches:
            print(f"Finding: {p.get('finding_id')} - {p.get('explanation')}")
            print("Patched Code:")
            print(p.get("patched_snippet"))
            print()
    print("=" * 60 + "\n")


def main(argv=None):
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="codereviewgraph",
        description="Stateful Multi-Agent Code Auditor powered by LangGraph & LangChain"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Audit a code file or snippet")
    audit_parser.add_argument("file", nargs="?", default=None, help="Path to file to audit")
    audit_parser.add_argument("--code", "-c", type=str, default=None, help="Inline code string to audit")
    audit_parser.add_argument("--output", "-o", type=str, default=None, help="Save markdown report to file")

    args = parser.parse_args(argv)

    if args.command == "audit":
        code_to_review = ""
        file_path = None
        if args.file:
            path = Path(args.file)
            if not path.is_file():
                print(f"Error: File '{args.file}' does not exist.", file=sys.stderr)
                sys.exit(1)
            code_to_review = path.read_text(encoding="utf-8")
            file_path = str(path)
        elif args.code:
            code_to_review = args.code
        else:
            print("Error: Specify either a file path or --code '...'", file=sys.stderr)
            sys.exit(1)

        thread_id = str(uuid.uuid4())
        initial_state = {
            "raw_code": code_to_review,
            "language": "python",
            "file_path": file_path,
            "current_stage": "STARTED"
        }
        
        try:
            result = review_app.invoke(initial_state, config={"configurable": {"thread_id": thread_id}})
            report = result.get("final_report", {})
            print_report_summary(report)

            if args.output:
                Path(args.output).write_text(report.get("markdown_report", ""), encoding="utf-8")
                print(f"Markdown report saved to: {args.output}")

            # Non-zero exit code if critical or high findings exist
            if report.get("critical_count", 0) > 0 or report.get("high_count", 0) > 0:
                sys.exit(2)
            sys.exit(0)
        except Exception as e:
            print(f"Audit failed: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
