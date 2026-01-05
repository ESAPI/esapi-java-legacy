package org.owasp.esapi.reference.validation.annotations;

import static org.junit.Assert.assertEquals;
import static org.owasp.esapi.PropNames.DISABLE_INTRUSION_DETECTION;

import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.SecurityConfigurationWrapper;
import org.owasp.esapi.http.MockHttpServletRequest;

public class ValidationAnnotationsTest {
    private static final boolean IS_WINDOWS = System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
    private static final String WINDOWS_ROOT = "C:\\";
    private static final String UNIX_ROOT = "/";

    private static class ConfOverride extends SecurityConfigurationWrapper {
        ConfOverride(SecurityConfiguration orig) {
            super(orig);
        }

        @Override
        public Boolean getBooleanProp(String propName) {
            if (DISABLE_INTRUSION_DETECTION.equals(propName)) {
                return Boolean.TRUE;
            }
            return super.getBooleanProp(propName);
        }
    }

    private Validator validator;

    @Before
    public void setUp() {
        ESAPI.override(new ConfOverride(ESAPI.securityConfiguration()));
        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }

    @After
    public void tearDown() {
        ESAPI.override(null);
    }

    @Test
    public void testValidCreditCard() {
        CreditCardBean bean = new CreditCardBean("1234 9876 0000 0008");
        assertViolations(bean, 0);
        bean.number = "4417 1234 5678 9112";
        assertViolations(bean, 1);
    }

    @Test
    public void testValidDate() {
        String validDate = DateFormat.getDateInstance(DateFormat.SHORT, Locale.US).format(new Date(0));
        DateBean bean = new DateBean(validDate);
        assertViolations(bean, 0);
        bean.value = "not-a-date";
        assertViolations(bean, 1);
    }

    @Test
    public void testValidDirectoryPath() {
        if (IS_WINDOWS) {
            Assume.assumeTrue(isSystemDriveC());
            DirectoryPathWindowsBean bean = new DirectoryPathWindowsBean(WINDOWS_ROOT);
            assertViolations(bean, 0);
            bean.path = WINDOWS_ROOT + "does-not-exist";
            assertViolations(bean, 1);
        } else {
            DirectoryPathUnixBean bean = new DirectoryPathUnixBean(UNIX_ROOT);
            assertViolations(bean, 0);
            bean.path = UNIX_ROOT + "does-not-exist";
            assertViolations(bean, 1);
        }
    }

    @Test
    public void testValidDouble() {
        DoubleBean bean = new DoubleBean("1.0");
        assertViolations(bean, 0);
        bean.value = "ridiculous";
        assertViolations(bean, 1);
    }

    @Test
    public void testValidFileContent() {
        FileContentBean bean = new FileContentBean("12345".getBytes(StandardCharsets.UTF_8));
        assertViolations(bean, 0);
        bean.content = "123456".getBytes(StandardCharsets.UTF_8);
        assertViolations(bean, 1);
    }

    @Test
    public void testValidFileName() {
        FileNameBean bean = new FileNameBean("test.txt");
        assertViolations(bean, 0);
        bean.name = "test.exe";
        assertViolations(bean, 1);
    }

    @Test
    public void testValidFileUpload() {
        if (IS_WINDOWS) {
            Assume.assumeTrue(isSystemDriveC());
            FileUploadWindowsBean bean = new FileUploadWindowsBean("12345".getBytes(StandardCharsets.UTF_8));
            assertViolations(bean, 0);
            bean.content = "123456".getBytes(StandardCharsets.UTF_8);
            assertViolations(bean, 1);
        } else {
            FileUploadUnixBean bean = new FileUploadUnixBean("12345".getBytes(StandardCharsets.UTF_8));
            assertViolations(bean, 0);
            bean.content = "123456".getBytes(StandardCharsets.UTF_8);
            assertViolations(bean, 1);
        }
    }

    @Test
    public void testValidInteger() {
        IntegerBean bean = new IntegerBean("5");
        assertViolations(bean, 0);
        bean.value = "20";
        assertViolations(bean, 1);
    }

    @Test
    public void testValidListItem() {
        ListItemBean bean = new ListItemBean("red");
        assertViolations(bean, 0);
        bean.value = "blue";
        assertViolations(bean, 1);
    }

    @Test
    public void testValidNumber() {
        NumberBean bean = new NumberBean("10");
        assertViolations(bean, 0);
        bean.value = "1000";
        assertViolations(bean, 1);
    }

    @Test
    public void testValidPrintableChars() {
        PrintableCharsBean bean = new PrintableCharsBean("Hello".toCharArray());
        assertViolations(bean, 0);
        bean.value = "Hi\n".toCharArray();
        assertViolations(bean, 1);
    }

    @Test
    public void testValidPrintableString() {
        PrintableStringBean bean = new PrintableStringBean("Hello");
        assertViolations(bean, 0);
        bean.value = "Hi\n";
        assertViolations(bean, 1);
    }

    @Test
    public void testValidRedirectLocation() {
        RedirectBean bean = new RedirectBean("/test/ok");
        assertViolations(bean, 0);
        bean.value = "http://example.com";
        assertViolations(bean, 1);
    }

    @Test
    public void testValidSafeHTML() {
        SafeHtmlBean bean = new SafeHtmlBean("<b>Jeff</b>");
        assertViolations(bean, 0);
        bean.value = "Test. <script>alert(document.cookie)</script>";
        assertViolations(bean, 1);
    }

    @Test
    public void testValidURI() {
        UriBean bean = new UriBean("http://example.com");
        assertViolations(bean, 0);
        bean.value = "javascript:alert(1)";
        assertViolations(bean, 1);
    }

    @Test
    public void testValidHTTPRequestParameterSet() {
        MockHttpServletRequest validRequest = new MockHttpServletRequest();
        validRequest.addParameter("required", "value");
        validRequest.addParameter("optional", "value");
        HttpRequestBean bean = new HttpRequestBean(validRequest);
        assertViolations(bean, 0);

        MockHttpServletRequest invalidRequest = new MockHttpServletRequest();
        bean.request = invalidRequest;
        assertViolations(bean, 1);
    }

    private boolean isSystemDriveC() {
        String systemDrive = System.getenv("SystemDrive");
        return systemDrive == null || "C:".equalsIgnoreCase(systemDrive);
    }

    private <T> void assertViolations(T bean, int expected) {
        Set<ConstraintViolation<T>> violations = validator.validate(bean);
        assertEquals(expected, violations.size());
    }

    private static class CreditCardBean {
        @ValidCreditCard(context = "cc", allowNull = false)
        private String number;

        CreditCardBean(String number) {
            this.number = number;
        }
    }

    private static class DateBean {
        @ValidDate(context = "date", dateStyle = DateFormat.SHORT, locale = "en-US", allowNull = false)
        private String value;

        DateBean(String value) {
            this.value = value;
        }
    }

    private static class DirectoryPathWindowsBean {
        @ValidDirectoryPath(context = "dir", parent = WINDOWS_ROOT, allowNull = false)
        private String path;

        DirectoryPathWindowsBean(String path) {
            this.path = path;
        }
    }

    private static class DirectoryPathUnixBean {
        @ValidDirectoryPath(context = "dir", parent = UNIX_ROOT, allowNull = false)
        private String path;

        DirectoryPathUnixBean(String path) {
            this.path = path;
        }
    }

    private static class DoubleBean {
        @ValidDouble(context = "double", minValue = 0, maxValue = 20, allowNull = false)
        private String value;

        DoubleBean(String value) {
            this.value = value;
        }
    }

    private static class FileContentBean {
        @ValidFileContent(context = "content", maxBytes = 5, allowNull = false)
        private byte[] content;

        FileContentBean(byte[] content) {
            this.content = content;
        }
    }

    private static class FileNameBean {
        @ValidFileName(context = "filename", allowedExtensions = {".txt"}, allowNull = false)
        private String name;

        FileNameBean(String name) {
            this.name = name;
        }
    }

    private static class FileUploadWindowsBean {
        @ValidFileUpload(
            context = "upload",
            directoryPath = WINDOWS_ROOT,
            fileName = "test.txt",
            parent = WINDOWS_ROOT,
            maxBytes = 5,
            allowNull = false
        )
        private byte[] content;

        FileUploadWindowsBean(byte[] content) {
            this.content = content;
        }
    }

    private static class FileUploadUnixBean {
        @ValidFileUpload(
            context = "upload",
            directoryPath = UNIX_ROOT,
            fileName = "test.txt",
            parent = UNIX_ROOT,
            maxBytes = 5,
            allowNull = false
        )
        private byte[] content;

        FileUploadUnixBean(byte[] content) {
            this.content = content;
        }
    }

    private static class IntegerBean {
        @ValidInteger(context = "int", minValue = 0, maxValue = 10, allowNull = false)
        private String value;

        IntegerBean(String value) {
            this.value = value;
        }
    }

    private static class ListItemBean {
        @ValidListItem(context = "item", list = {"red", "green"}, allowNull = false)
        private String value;

        ListItemBean(String value) {
            this.value = value;
        }
    }

    private static class NumberBean {
        @ValidNumber(context = "num", minValue = 1, maxValue = 100, allowNull = false)
        private String value;

        NumberBean(String value) {
            this.value = value;
        }
    }

    private static class PrintableCharsBean {
        @ValidPrintable(context = "print", maxLength = 10, allowNull = false)
        private char[] value;

        PrintableCharsBean(char[] value) {
            this.value = value;
        }
    }

    private static class PrintableStringBean {
        @ValidPrintable(context = "print", maxLength = 10, allowNull = false)
        private String value;

        PrintableStringBean(String value) {
            this.value = value;
        }
    }

    private static class RedirectBean {
        @ValidRedirectLocation(context = "redirect", allowNull = false)
        private String value;

        RedirectBean(String value) {
            this.value = value;
        }
    }

    private static class SafeHtmlBean {
        @ValidSafeHTML(context = "safehtml", maxLength = 200, allowNull = false)
        private String value;

        SafeHtmlBean(String value) {
            this.value = value;
        }
    }

    private static class UriBean {
        @ValidURI(context = "uri", allowNull = false)
        private String value;

        UriBean(String value) {
            this.value = value;
        }
    }

    private static class HttpRequestBean {
        @ValidHTTPRequestParameterSet(
            context = "params",
            requiredNames = {"required"},
            optionalNames = {"optional"},
            allowNull = false
        )
        private HttpServletRequest request;

        HttpRequestBean(HttpServletRequest request) {
            this.request = request;
        }
    }
}
