package com.mildo.user;

import com.mildo.user.Vo.AccessVO;
import com.mildo.user.Vo.LevelCountDTO;
import com.mildo.user.Vo.TokenVO;
import com.mildo.user.Vo.UserVO;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    @ResponseBody
    @GetMapping(value = "/{userId}/info", produces = "application/json; charset=UTF-8")
    public ResponseEntity<UserVO> userInfo(@PathVariable String userId) {
        UserVO user = userService.finduserId(userId);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }
        return ResponseEntity.ok(user);
    }

    @ResponseBody
    @GetMapping(value="/{userId}/tokenInfo", produces="application/json; charset=UTF-8")
    public ResponseEntity<AccessVO> tokenInfo(@PathVariable String userId, HttpServletRequest request, HttpServletResponse response){
        TokenVO token = userService.makeToken(userId);

        if (token == null || token.getRefreshToken() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        String refreshToken = token.getRefreshToken();
        Cookie refreshTokenCookie = new Cookie("RefreshToken", refreshToken);

        refreshTokenCookie.setHttpOnly(true); // 자바스크립트 접근 불가
        refreshTokenCookie.setSecure(true); // HTTPS에서만 전송
        refreshTokenCookie.setPath("/"); // 애플리케이션 전역에서 사용 가능
        refreshTokenCookie.setMaxAge(-1); // 세션 동안 유효, 브라우저 종료 시 쿠키 삭제됨
        refreshTokenCookie.setDomain("api.mildo.xyz"); // 도메인 설정
        refreshTokenCookie.setAttribute("SameSite", "None"); // SameSite 속성 설정
        response.addCookie(refreshTokenCookie);

        AccessVO result = userService.findAccessToken(userId);
        return ResponseEntity.ok(result);
    }

    @ResponseBody
    @GetMapping(value="/{userId}/solvedLevels", produces="application/json; charset=UTF-8")
    public ResponseEntity<?> solvedLevelsId(@PathVariable String userId){
        List<LevelCountDTO> solvedLevels = userService.solvedLevelsList(userId);
        return solvedLevels == null ? ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null) : ResponseEntity.ok(solvedLevels);
    }

    @ResponseBody
    @GetMapping(value="/{userId}/studyOut", produces="application/json; charset=UTF-8")
    public ResponseEntity<String> studyOut(@PathVariable String userId){
        UserVO user = userService.finduserId(userId);

        if(user == null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        if("Y".equals(user.getUserLeader())){
            return ResponseEntity.ok("리더는 탈퇴 위임하고 해");
        } else {
            int res = userService.studyGetOut(userId);
            return res > 0 ? ResponseEntity.ok("탈퇴 성공") : ResponseEntity.status(HttpStatus.BAD_REQUEST).body("탈퇴 실패");
        }
    }

    @ResponseBody
    @GetMapping(value="/{userId}/userTotalSolved", produces="application/json; charset=UTF-8")
    public ResponseEntity<?> userTotalSolved(@PathVariable String userId){
        Integer res = userService.userTotalSolved(userId);

        if(res == null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("userId not found");
        }

        Map<String, Object> response = new HashMap<>();
        response.put("user_solvedproblem", res);
        return ResponseEntity.ok(response);
    }

    @ResponseBody
    @GetMapping(value="/{userId}/service-out", produces="application/json; charset=UTF-8")
    public ResponseEntity<String> serviceOut(@PathVariable String userId, HttpServletResponse response){
        UserVO user = userService.finduserId(userId);
        if(user == null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("userId not found");
        }
        deleteRefreshTokenCookie(response);
        int res = userService.serviceOut(userId);
        deleteRefreshTokenCookie(response);
        return res > 0 ? ResponseEntity.ok("탈퇴 성공") : ResponseEntity.status(HttpStatus.BAD_REQUEST).body("탈퇴 실패");
    }

    @PostMapping("/{userId}/google-logout")
    public ResponseEntity<String> logout(@PathVariable String userId, HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication); // 세션 무효화 및 SecurityContext 초기화
        }

        deleteRefreshTokenCookie(response);

        String result = userService.blackToken(userId);
        String message = "토큰이 없음".equals(result) ? "토큰은 없지만 로그아웃 성공" : "로그아웃 성공";
        return ResponseEntity.ok(message);
    }

    private void deleteRefreshTokenCookie(HttpServletResponse response) {
        Cookie myCookie = new Cookie("RefreshToken", null);
        myCookie.setMaxAge(0); // 쿠키의 expiration 타임을 0으로 하여 없앤다.
        myCookie.setPath("/");
        myCookie.setHttpOnly(true);
        myCookie.setSecure(true);
        myCookie.setDomain("api.mildo.xyz");
        myCookie.setAttribute("SameSite", "None");
        response.addCookie(myCookie);
        response.setHeader("Set-Cookie", "RefreshToken=; Path=/; Domain=api.mildo.xyz; Max-Age=0; Secure; HttpOnly; SameSite=None");
    }

    @ResponseBody
    @PatchMapping(value = "/{userId}", produces="application/json; charset=UTF-8")
    public ResponseEntity<?> updateUser(@PathVariable String userId, @RequestBody UserVO vo) {
        UserVO user = userService.finduserId(userId);
        if(user == null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("userId not found");
        }
        int res = userService.changUserInfo(userId, vo);
        return res > 0 ? ResponseEntity.ok("변경 성공") : ResponseEntity.status(HttpStatus.BAD_REQUEST).body("변경 실패");
    }

}
