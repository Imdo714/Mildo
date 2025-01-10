//package com.mildo.study;
//
//import com.mildo.code.CodeController;
//import lombok.extern.slf4j.Slf4j;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;
//import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//@Slf4j
//@WebMvcTest(StudyController.class)
//class StudyControllerTest {
//
//    @BeforeEach         // 테스트 케이스를 시작하기 전마다 실행
//    void setUp() {
//    }
//
//    @DisplayName("스터디 생성 테스트")
//    @Test
//    void create() {
//        // given = 테스트 실행을 준비하는 단계 (어떤 상황, 데이터가 주어졌을 때)
//        // when = 테스트를 진행하는 단계 (어떤 함수를 실행시키면 )
//        // then = 테스트 결과를 검증하는 단계 (어떤 결과가 기대된다.)
//    }
//
//    @DisplayName("스터디 리스트 가져오기 테스트")
//    @Test
//    void studyList() {
//        // given = 테스트 실행을 준비하는 단계 (어떤 상황, 데이터가 주어졌을 때)
//        // when = 테스트를 진행하는 단계 (어떤 함수를 실행시키면 )
//        // then = 테스트 결과를 검증하는 단계 (어떤 결과가 기대된다.)
//    }
//
//    @DisplayName("멤버 수 테스트")
//    @Test
//    void membersCount() {
//        // given = 테스트 실행을 준비하는 단계 (어떤 상황, 데이터가 주어졌을 때)
//        // when = 테스트를 진행하는 단계 (어떤 함수를 실행시키면 )
//        // then = 테스트 결과를 검증하는 단계 (어떤 결과가 기대된다.)
//    }
//
//    @DisplayName("남은 일수 테스트")
//    @Test
//    void studyDay() {
//        // given = 테스트 실행을 준비하는 단계 (어떤 상황, 데이터가 주어졌을 때)
//        // when = 테스트를 진행하는 단계 (어떤 함수를 실행시키면 )
//        // then = 테스트 결과를 검증하는 단계 (어떤 결과가 기대된다.)
//    }
//
//    @DisplayName("스터디 등수 가져오기 테스트")
//    @Test
//    void ranks() {
//        // given = 테스트 실행을 준비하는 단계 (어떤 상황, 데이터가 주어졌을 때)
//        // when = 테스트를 진행하는 단계 (어떤 함수를 실행시키면 )
//        // then = 테스트 결과를 검증하는 단계 (어떤 결과가 기대된다.)
//    }
//
//    @DisplayName("스터디 참가하기 테스트")
//    @Test
//    void enterStudy() {
//        // given = 테스트 실행을 준비하는 단계 (어떤 상황, 데이터가 주어졌을 때)
//        // when = 테스트를 진행하는 단계 (어떤 함수를 실행시키면 )
//        // then = 테스트 결과를 검증하는 단계 (어떤 결과가 기대된다.)
//    }
//
//    @DisplayName("밀도심기 테스트")
//    @Test
//    void monthData() {
//        // given = 테스트 실행을 준비하는 단계 (어떤 상황, 데이터가 주어졌을 때)
//        // when = 테스트를 진행하는 단계 (어떤 함수를 실행시키면 )
//        // then = 테스트 결과를 검증하는 단계 (어떤 결과가 기대된다.)
//    }
//
//    @DisplayName("스터디 이름 바꾸기 테스트")
//    @Test
//    void updateUser() {
//        // given = 테스트 실행을 준비하는 단계 (어떤 상황, 데이터가 주어졌을 때)
//        // when = 테스트를 진행하는 단계 (어떤 함수를 실행시키면 )
//        // then = 테스트 결과를 검증하는 단계 (어떤 결과가 기대된다.)
//    }
//
//    @DisplayName("스터디 리더 변경 기능 테스트")
//    @Test
//    void updateLeader() {
//        // given = 테스트 실행을 준비하는 단계 (어떤 상황, 데이터가 주어졌을 때)
//        // when = 테스트를 진행하는 단계 (어떤 함수를 실행시키면 )
//        // then = 테스트 결과를 검증하는 단계 (어떤 결과가 기대된다.)
//    }
//
//    @DisplayName("스터디 삭제 기능 테스트")
//    @Test
//    void deleteStudy() {
//        // given = 테스트 실행을 준비하는 단계 (어떤 상황, 데이터가 주어졌을 때)
//        // when = 테스트를 진행하는 단계 (어떤 함수를 실행시키면 )
//        // then = 테스트 결과를 검증하는 단계 (어떤 결과가 기대된다.)
//    }
//}