import csv
from collections import defaultdict
import json
from pathlib import Path
from typing import TypeAlias

# 복잡한 타입에 대한 별칭을 만들어 가독성을 높입니다.
CheckIdVectorMap: TypeAlias = dict[str, dict[str, str]]


def map_vectors_by_check_id(file_path: Path) -> CheckIdVectorMap:
    """
    취약점 파일을 읽어 각 check_id에 벡터(리소스)를 매핑.

    Args:
        file_path: 취약점 파일 경로.

    Returns:
        키는 check_id, 값은 {vector: description} 형태인 딕셔너리.

    Raises:
        FileNotFoundError: file_path가 존재하지 않음.
        Exception: 그 외 파싱 오류가 발생.
    """
    vectors_by_id = defaultdict(dict)

    # 함수는 이제 데이터 변환에만 집중하고, 파일 관련 에러 처리는 호출자에게 위임합니다.
    with open(file_path, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile, delimiter="\t")

        for row in reader:
            if not row or len(row) < 5:
                continue

            check_id = row[1].strip()
            vector = row[3].strip()
            description = row[4].strip()
            if vector not in vectors_by_id[check_id]:
                vectors_by_id[check_id][vector] = description

    return dict(vectors_by_id)


def main() -> None:
    """Main execution function for standalone script usage."""
    input_file = Path("terraformaws.csv")
    output_file = Path("mapped_vectors.json")

    try:
        mapped_vectors = map_vectors_by_check_id(input_file)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(mapped_vectors, f, indent=2, ensure_ascii=False)
        print(f"성공적으로 결과를 '{output_file}' 파일에 저장했습니다.")
    except FileNotFoundError:
        print(f"오류: 입력 파일 '{input_file}'을(를) 찾을 수 없습니다.")
    except IOError as e:
        print(f"오류: 파일 '{output_file}'을(를) 쓰는 중 오류가 발생했습니다: {e}")
    except Exception as e:
        print(f"오류: 처리 중 예기치 않은 오류가 발생했습니다: {e}")


if __name__ == "__main__":
    main()
