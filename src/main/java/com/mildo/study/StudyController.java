package com.mildo.study;

import com.mildo.study.Vo.EnterStudy;
import com.mildo.study.Vo.StudyVO;
import com.mildo.user.UserService;
import com.mildo.user.Vo.UserVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/study")
public class StudyController {
    private final StudyService studyService;
    private final UserService userService;

    @GetMapping
    public String index() {
        return "Study Home";
    }

    // 유저 생성
    @ResponseBody
    @PostMapping(value="/{userId}/create", produces="application/json; charset=UTF-8")
    public ResponseEntity<Map<String, Object>> create(@PathVariable String userId, @RequestBody StudyVO studyVO) {

        // 유저 아이디 검증 (존재하는 아이디인지 + 토큰 검증)
        Map<String, Object> response = new HashMap<>();
        UserVO userVO = userService.finduserId(userId);

        if(userVO == null){
            response.put("error", "userId not found");
            return ResponseEntity.status(UNAUTHORIZED).body(response);
        }

        if(userVO.getStudyId() != null) { // 유저 studyId가 있으면 null 반납
            response.put("studyId", userVO.getStudyId());
            response.put("is_participainted", true);
            return ResponseEntity.ok(response);
        }

        String studyId = studyService.create(userId, studyVO);
        response.put("studyId", studyId);
        return ResponseEntity.ok(response);
    }

    //스터디별 유저 리스트
    @GetMapping("/{studyId}/memberList")
    public ResponseEntity<?> studyList(@PathVariable String studyId) {
        String validated = validateStudyId(studyId);

        if (validated != null)
            return ResponseEntity.status(UNAUTHORIZED).body(validated);

        return ResponseEntity.ok(studyService.studyList(studyId));
    }

    //스터디 인원 세기
    @GetMapping("/{studyId}/membersCount")
    public ResponseEntity<Map<String, Object>> membersCount(@PathVariable String studyId) {
        Map<String, Object> response = new HashMap<>();

        String validated = validateStudyId(studyId);
        if (validated != null){
            response.put("error", validated);
            return ResponseEntity.status(UNAUTHORIZED).body(response);

        }
        int totalMembers = studyService.totalMembers(studyId);

        response.put("totalMembers", totalMembers);

        return ResponseEntity.ok(response);
    }


    //스터디  남은 일수, 진행 한 수
    @GetMapping("/{studyId}/studyDays")
    public ResponseEntity<?> studyDay(@PathVariable String studyId) {
        String validated = validateStudyId(studyId);

        if (validated != null){
            Map<String, Object> response = new HashMap<>();
            response.put("error", validated);
            return ResponseEntity.status(UNAUTHORIZED).body(response);
        }

        return ResponseEntity.ok(studyService.studyDays(studyId));
    }

    //스터디 이름
    @GetMapping("/{studyId}/studyName")
    public ResponseEntity<String> getStudyName(@PathVariable String studyId) {
        String studyName = studyService.getStudyName(studyId);

        if(studyName == null){
            return ResponseEntity.status(UNAUTHORIZED).body("studyId not found");
        }

        return ResponseEntity.ok(studyName);
    }

    // studyId로 스터디 등수 가져오기
    @GetMapping("/{studyId}/rank")
    public ResponseEntity<?> ranks(@PathVariable String studyId) {
        String validated = validateStudyId(studyId);

        if (validated != null){
            Map<String, Object> response = new HashMap<>();
            response.put("error", validated);
            return ResponseEntity.status(UNAUTHORIZED).body(response);
        }

        List<StudyVO> totalrank = studyService.totalrank(studyId);
        return ResponseEntity.ok(totalrank);
    }

    //스터디 참가하기
    @ResponseBody
    @PutMapping(value="/enterStudy", produces="application/json; charset=UTF-8")
    public ResponseEntity<String> enterStudy(@RequestBody EnterStudy enterStudy) {
        String studyId = enterStudy.getStudyId();

        String validated = validateStudyId(studyId);
        if (validated != null){
            return ResponseEntity.status(UNAUTHORIZED).body(validated);
        }

        int res = studyService.totalMembers(studyId);
        if(res >= 6){
            return ResponseEntity.status(BAD_REQUEST).body("인원 초과");
        }

        UserVO userVO = userService.finduserId(enterStudy.getUserId());
        if(userVO == null){
            return ResponseEntity.status(UNAUTHORIZED).body("userId not found");
        }

        if(userVO.getStudyId() != null){
            log.info("userVO.getStudyId() = {}", userVO.getStudyId());
            return ResponseEntity.status(BAD_REQUEST).body("이미 스터디가 있습니다. Study ID: "+ userVO.getStudyId());
        }

        boolean isValid = studyService.checkstudyIdPassword(enterStudy); // 비번 체크
        if (isValid) {
            userService.updateStudyId(enterStudy);
            return ResponseEntity.ok("스터디 접속 완료");
        } else {
            return ResponseEntity.status(BAD_REQUEST).body("Invalid study code or password!");
        }
    }

    //스터디 밀도심기
    @GetMapping("{studyId}/monthData")
    public ResponseEntity<List<Map<String, Object>>> monthData(@PathVariable String studyId){
        String validated = validateStudyId(studyId);

        if (validated != null){
            List<Map<String, Object>> list = new ArrayList<>();
            Map<String, Object> response = new HashMap<>();
            response.put("error", validated);
            list.add(response);
            return ResponseEntity.status(UNAUTHORIZED).body(list);
        }

        return ResponseEntity.ok(studyService.Mildo(studyId));
    }

    // 스터디 이름 바꾸기 구현
    @ResponseBody
    @PutMapping(value = "/{studyId}/rename", produces="application/json; charset=UTF-8")
    public ResponseEntity<String> updateUser(@PathVariable String studyId, @RequestBody StudyVO vo) {
        String validated = validateStudyId(studyId);
        if (validated != null){
            return ResponseEntity.status(UNAUTHORIZED).body(validated);
        }

        return studyService.updateStudyName(studyId, vo.getStudyName()) > 0 ? ResponseEntity.ok("변경 성공") : ResponseEntity.ok("변경 실패");
    }

    // 스터디 리더 변경 기능 구현
    @PutMapping("/{studyId}/update-leader")
    public ResponseEntity<String> updateLeader(@PathVariable String studyId, @RequestBody Map<String, String> requestBody){
        String validated = validateStudyId(studyId);
        if (validated != null){
            return ResponseEntity.status(UNAUTHORIZED).body(validated);
        }

        String newLeaderId = requestBody.get("newLeaderId");
        String leaderId = studyService.updateLeader(studyId, newLeaderId);

        if (leaderId.isEmpty())
            return ResponseEntity.status(NOT_FOUND).body(null); // 404

        return ResponseEntity.ok(newLeaderId);
    }

    // 스터디 삭제 기능 구현
    @DeleteMapping("/{studyId}/delete-study")
    public ResponseEntity<Boolean> deleteStudy(@PathVariable String studyId){
        int res = studyService.deleteStudyUser(studyId); // 회원 정보 수정, 코드, 댓글 다 삭제
        
        boolean isValid =  studyService.deleteStudy(studyId); // 스터디 삭제인 듯
        if (!isValid) {
            return ResponseEntity.status(NOT_FOUND).body(null); // 404
        }

        return ResponseEntity.ok(true);
    }

    private String validateStudyId(@PathVariable String studyId) {
        if(studyService.getStudyName(studyId) == null){
            return "studyId not found";
        }
        return null;
    }
}
