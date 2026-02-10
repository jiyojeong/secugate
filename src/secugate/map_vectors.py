import csv
from collections import defaultdict
import json

def map_vectors_by_check_id(file_path):
    """
    Reads a vulnerability file and maps vectors (resources) to each check_id.

    Args:
        file_path (str): The path to the vulnerability file.

    Returns:
        dict: A dictionary where keys are check_ids and values are lists of associated vectors.
    """
    vectors_by_id = defaultdict(list)
    
    try:
        with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
            # The file is tab-separated
            reader = csv.reader(csvfile, delimiter='\t')
            
            for row in reader:
                # 행에 최소 5개의 열이 있는지 확인하여 IndexError를 방지합니다.
                if not row or len(row) < 5:
                    continue
                
                check_id = row[1].strip()
                vector = row[3].strip()  # 'Resource'를 벡터로 가정합니다.
                description = row[4].strip()  # 오타 수정: descrition -> description
                if vector not in vectors_by_id[check_id]:
                    vectors_by_id[check_id].append(vector)
                    vectors_by_id[check_id].append(description)

    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
        
    return dict(vectors_by_id)

if __name__ == "__main__":
    input_file = 'terraformaws.cvs'
    output_file = 'mapped_vectors.json'
    mapped_vectors = map_vectors_by_check_id(input_file)
    if mapped_vectors:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                # 한글 등이 깨지지 않도록 ensure_ascii=False 옵션을 사용합니다.
                json.dump(mapped_vectors, f, indent=2, ensure_ascii=False)
            print(f"성공적으로 결과를 '{output_file}' 파일에 저장했습니다.")
        except IOError as e:
            print(f"파일 '{output_file}'을 쓰는 중 오류가 발생했습니다: {e}")
