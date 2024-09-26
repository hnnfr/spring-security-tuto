package fr.algofi.hnn.springsecuritytuto.dto;

import com.fasterxml.jackson.annotation.JsonBackReference;
import lombok.Data;

@Data
public class OpinionDto {
    @JsonBackReference(value = "user-opinions")
    private UserDto user;

    @JsonBackReference(value = "topic-opinions")
    private TopicDto topic;

    private String details;
    private String scope;

    @Override
    public String toString() {
        return "OpinionDto [details=" + details + " user=" + user.getEmail() + ", topic=" + topic.getName() + "]";
    }
}
