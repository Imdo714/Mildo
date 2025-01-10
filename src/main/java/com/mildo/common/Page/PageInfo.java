package com.mildo.common.Page;

import lombok.Data;

@Data
public class PageInfo {

    private int listCount;      //현재 총 게시글 수
    private int currentPage;    //현재 페이지(즉, 사용자가 요청한 페이지)
    private int pageLimit;      //페이지 하단에 보여질 페이징바의 페이지 최대의 개수
    private int boardLimit;     //한 페이지내에 보여질 게시글 최대갯수(먗개 단위씩)
    private int maxPage;        // 가장 마지막페이지(총 페이지 수)
    private int startPage;      // 페이징바의 시작수
    private int endPage;        // 페이징바의 끝수

    public PageInfo(){}

    public PageInfo(int listCount, int currentPage, int pageLimit, int boardLimit, int maxPage, int startPage, int endPage) {
        this.listCount = listCount;
        this.currentPage = currentPage;
        this.pageLimit = pageLimit;
        this.boardLimit = boardLimit;
        this.maxPage = maxPage;
        this.startPage = startPage;
        this.endPage = endPage;
    }
}
