package com.mildo.study;


import com.mildo.study.Vo.EnterStudy;
import com.mildo.study.Vo.RemainingDaysDTO;
import com.mildo.study.Vo.StudyVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

import java.util.List;

@Slf4j
@Repository
@RequiredArgsConstructor
public class StudyRepository {

    public void create(StudyVO study){
        StudyDBManger.create(study);
    }

    public List<StudyVO> studyList(String studyId){
        return StudyDBManger.studyList(studyId);
    }

    public int totalMembers(String studyId){
        return StudyDBManger.totalMembers(studyId);
    }

    public RemainingDaysDTO studyDays(String studyId){
        return StudyDBManger.studyDays(studyId);
    }

    public RemainingDaysDTO studyDaysRe(String studyId){
        return StudyDBManger.studyDaysRe(studyId);
    }

    public List<StudyVO> totalrank(String studyId){
        return StudyDBManger.totalrank(studyId);
    }

    public String getStartMonth(String studyId){
        return StudyDBManger.getStartMonth(studyId);
    }

    public Object getStudyMemberByMonth(String studyId, String month, String subDate) {
        return StudyDBManger.getStudyMemberByMonth(studyId, month, subDate);
    }

    public Object getStudyMemberIdByMonth(String studyId, String month, String subDate) {
        return StudyDBManger.getStudyMemberIdByMonth(studyId, month, subDate);
    }

    public boolean checkstudyIdPassword(EnterStudy enteStudy) {
        return StudyDBManger.checkstudyIdPassword(enteStudy);
    }

    public int updateStudyName(String studyId, String studyName) {
        return StudyDBManger.updateStudyName(studyId, studyName);
    }

    public String updateLeader(String studyId,  String newLeaderId) {
        int success = StudyDBManger.updateLeader(studyId, newLeaderId);
        if(success != 1)
            return "";

        return newLeaderId;
    }

    public boolean deleteStudy(String studyId) {
        int success = StudyDBManger.deleteStudy(studyId);

        return success != 0;
    }

    public int deleteStudyUser(String studyId) {
        return StudyDBManger.deleteStudyUser(studyId);
    }

    public int deleteStudyCode(String studyId) {
        return StudyDBManger.deleteStudyCode(studyId);
    }

    public int deleteStudyComment(String studyId) {
        return StudyDBManger.deleteStudyComment(studyId);
    }

    public StudyVO findStudyNo(int studyNo) {
        return StudyDBManger.findStudyNo(studyNo);
    }

    public int findStudyNextNo() {
        return StudyDBManger.findStudyNextNo();
    }

    public int createStudyId(String studyId) {
        return StudyDBManger.createStudyId(studyId);
    }

    public String findNullStudyId(){return StudyDBManger.findNullStudyId();}

    public void saveStudy(StudyVO studyVo) {StudyDBManger.saveStudy(studyVo);}

    public String getStudyName(String studyId) {
        return StudyDBManger.getStudyName(studyId);
    }

    public String subDate(String studyId) {
        return StudyDBManger.subDate(studyId);
    }
}
