# benchmarks/targets.py
"""
Central place to define benchmark targets and benchmark suites.

- BENCHMARKS: which repos we care about (and how each tool refers to them)
- BENCHMARK_SUITES: which benchmark types we support (runtime, etc.)
"""

BENCHMARKS = {
    "juice_shop": {
        "label": "Juice Shop",
        "repo_url": "https://github.com/juice-shop/juice-shop.git",
        "aikido_ref": "Chai80/juice-shop",
        "sonar_project_key": "chai80_juice_shop",
    },
    "dvpwa": {
        "label": "DVPWA",
        "repo_url": "https://github.com/vulnerable-apps/dvpwa.git",
        "aikido_ref": "Chai80/dvpwa",
        "sonar_project_key": "chai80_dvpwa",
    },
    "owasp_benchmark": {
        "label": "OWASP Benchmark (Java)",
        "repo_url": "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
        "aikido_ref": "Chai80/owasp_benchmark",
        "sonar_project_key": "chai80_owasp_benchmark",
    },
    "spring_realworld": {
        "label": "Spring Boot RealWorld",
        "repo_url": (
            "https://github.com/gothinkster/"
            "spring-boot-realworld-example-app.git"
        ),
        "aikido_ref": "Chai80/spring_realworld",
        "sonar_project_key": "chai80_spring_realworld",
    },
    "vuln_node_express": {
        "label": "vuln_node_express",
        "repo_url": "https://github.com/vulnerable-apps/vuln_node_express.git",
        "aikido_ref": "Chai80/vuln_node_express",
        "sonar_project_key": "chai80_vuln_node_express",
    },
}

# For now we only have one benchmark suite, but this menu
# makes it easy to add more later.
BENCHMARK_SUITES = {
    "runtime": (
        "Runtime benchmark (run selected scanners and measure wall-clock time)"
    ),
}

__all__ = ["BENCHMARKS", "BENCHMARK_SUITES"]
