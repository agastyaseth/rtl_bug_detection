// CWE: CWE-203
module timing_sensitive_auth (
    input wire clk,
    input wire reset,
    input wire [31:0] password_hash,
    input wire [31:0] input_hash,
    input wire auth_request,
    output reg auth_result
);

    reg [3:0] compare_counter;
    reg [31:0] stored_hash;
    reg comparing;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            auth_result <= 1'b0;
            comparing <= 1'b0;
            compare_counter <= 4'b0;
            stored_hash <= 32'b0;
        end else begin
            if (auth_request) begin
                stored_hash <= password_hash;
                comparing <= 1'b1;
                compare_counter <= 4'b0;
            end

            if (comparing) begin
                // Simulate timing-dependent comparison
                if (stored_hash[compare_counter] == input_hash[compare_counter]) begin
                    compare_counter <= compare_counter + 1;
                    
                    // Intentionally variable timing based on bit match
                    if (stored_hash[compare_counter] == 1'b1) 
                        #2 compare_counter <= compare_counter + 1;
                end else begin
                    comparing <= 1'b0;
                    auth_result <= 1'b0;
                end

                // Observable timing discrepancy in authentication
                if (compare_counter == 4'b1111) begin
                    auth_result <= 1'b1;
                    comparing <= 1'b0;
                end
            end
        end
    end

endmodule