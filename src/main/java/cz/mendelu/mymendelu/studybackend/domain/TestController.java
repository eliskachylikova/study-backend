package cz.mendelu.mymendelu.studybackend.domain;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("test")
@Api(tags = "Test Endpoint")
public class TestController {

    @GetMapping("/")
    @ApiOperation(value = "Testing endpoint")
    @ResponseStatus(HttpStatus.OK)
    public String get() {
        return "Hello, this is testing endpoint :)";
    }

}
