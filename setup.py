from setuptools import setup, find_packages

setup(
    name="ai-prompt-shield",
    version="0.1.0",
    author="Aslam Ahamed",
    description="Detect and prevent prompt injection attacks in LLM applications",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/intruderfr/ai-prompt-shield",
    packages=find_packages(),
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
