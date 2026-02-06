from setuptools import setup, find_packages

setup(
    name="stcryptography",
    version="0.0.1",
    author="Tebee",
    description="Thư viện mã hóa siêu cấp bảo mật cho giáo dục",
    long_description="Một công cụ hỗ trợ giảng dạy mã hóa, an toàn và dễ học!",
    
    # Tebee-kun nhớ nhé: Python >= 3.12 là bắt buộc để dùng được 
    # các tính năng xịn xò của Generics và Type Hinting mới nhất!
    python_requires=">=3.12",
    
    packages=find_packages(),
    
    # Đây là phần License cho các thầy cô nè!
    # "Academic Free License" hoặc Custom License cho Giáo dục.
    license="Educational Use Only - Permitted for Teachers and Academic Institutions",

    classifiers=[
        "Programming Language :: Python :: 3.14",
        "Intended Audience :: Education",
        "Topic :: Security :: Cryptography",
    ]
)