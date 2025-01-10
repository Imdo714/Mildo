# SWYP7


# 의존성
------
- Spring Boot Starter Web
- MyBatis Spring Boot Starter
- PostgreSQL Driver
- Lombok (Optional)
- Spring Boot DevTools
- Spring Boot Starter Test
- MyBatis Spring Boot Starter Test


# ERD 
### 초기 ERD

![image](https://github.com/user-attachments/assets/df030931-b491-4870-8774-3af445b75081)

### 1차 변경

![image](https://github.com/user-attachments/assets/c250ccfa-1a52-4024-ab2b-b3913a1c4826)
- 스터디 테이블과 사용자 테이블의 1대 다 관계가 역전되어 있음
  - 스터디가 사용자 1명의 정보만을 갖고 있어, 사용자의 수만큼 테이블 개수가 만들어지는 문제 해결
  

- 구글 로그인에 대한 정보 추가


- 성별, 핸드폰이 설계와 맞지 않아서 사용자 테이블에서 제거


- 스터디 참가 여부 -> 스터디 번호의 유무로 판단


- 사용자가 언제 스터디에 참가했는지에 대한 정보 필요
  - 스터디 시작일 추가


- 코드문제설명에서 날짜 정보 가져오는 것은 비효율적이라 판단
  - 코드 푼 날짜 컬럼 추가
---

# 밀도 커밋 컨벤션
1. 제목과 본문을 한 줄 띄워 분리하기

    ex) 
    ```
    [STYLE] sqlMapConfig.xml 수정 및 db.properties 위치 변경
    
    resource 주소 변경
    classpath(resources 패키지)를 기준으로 하기에 경로에 맞게 수정
    ```
2. 제목은 한글 기준 30자 이내
3. 설명 일관되게 통일
   >ex) ~기능 구현, ~작성, ~출력, ~삭제, ~생성, ~수정 등
4. TYPE은 대문자로 통일    
   >ex) [FEAT], [FIX], [DOCS], [STYLE], ...

### TYPE 종류
>**FEAT**: 새로운 기능 (기능 구현)
> 
>**FIX**: 버그 수정
> 
>**DOCS**: documentation 변경
> 
>**STYLE**: 코드 의미에 영향을 주지 않는, 코드가 아닌 스타일에 관련된 변경사항(포맷, 공백, 빼먹은 세미콜론, 함수 이름 변경, 줄간격, 파일 이름, 의미없는 주석 삭제)
>
>**REFACTOR**: 리팩토링에 대한 커밋(버그를 수정하지 않고 기능을 추가하지 않는 코드 변경)
>
>**TEST**: 누락된 테스트 추가 또는 기존 테스트 수정
>
>**CHORE**: 패키지 매니저 설정할 경우, 코드 수정 없이 설정을 변경 (eslint, prettier... 패키지 설정)
