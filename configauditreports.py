import json
from terminaltables import AsciiTable
import textwrap
import subprocess
import pprint
import argparse
import loguru

logger = loguru.logger


def parse_args():
    parsers = argparse.ArgumentParser()

    parsers.add_argument(
        "--severity",
        required=False,
        type=str,
        default="",
        action="store",
        help="Vulnerability severity to filter on.",
    )
    return parsers.parse_args()


def get_trivy_report():
    report = subprocess.run(
        [
            "kubectl",
            "get",
            "configauditreports.aquasecurity.github.io",
            "-A",
            "-o",
            "json",
        ],
        capture_output=True,
    )
    report = json.loads(report.stdout)
    return report


def generate_report(severity, data):
    header = ["Name", "Kind", "Namespace", "Severity", "CheckID", "Description", "Messages", "Title"]
    table = [header]

    try:
        for report in data["items"]:
            kind = report["metadata"]["labels"]["trivy-operator.resource.kind"]
            name = report["metadata"]["name"]
            namespace = report["metadata"]["namespace"]
            try:
                for item in report["report"]["checks"]:
                    if item["severity"] == severity:
                        severity = item["severity"]
                        checkID = item["checkID"]
                        description = item["description"]
                        messages = item["messages"]
                        title = item["title"]

                        table.append(
                            [
                                name,
                                kind,
                                namespace,
                                severity,
                                checkID,
                                description,
                                messages,
                                title,
                            ]
                        )
            except KeyError as e:
                logger.error(f"KeyError: {e}")
                continue
    except KeyError as e:
        logger.error(f"KeyError: {e}")

    return table


def format_table(table):
    max_widths = [30, 15, 15, 10, 10, 50, 50, 15]  # Adjust these widths as needed

    # Function to wrap text in each cell and join it as a single string
    def wrap_and_join_text(cell, width):
        return "\n".join(textwrap.wrap(cell, width))

    wrapped_table = []
    for row in table:
        wrapped_row = [
            wrap_and_join_text(str(cell), max_widths[i]) for i, cell in enumerate(row)
        ]
        wrapped_table.append(wrapped_row)

    table_ascii = AsciiTable(wrapped_table)
    table_ascii.inner_row_border = True
    return table_ascii.table


def main():
    logger.info("Starting Trivy Parser")
    trivy_report = get_trivy_report()

    severity_list = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    args = parse_args()

    if args.severity:
        logger.info(f"Severity: {args.severity}")
        table = generate_report(args.severity, trivy_report)
        table = format_table(table)

        print(table)

    else:
        for severity in severity_list:
            logger.info(f"Severity: {severity}")
            table = generate_report(severity, trivy_report)
            table = format_table(table)

            print(table)


if __name__ == "__main__":
    main()
